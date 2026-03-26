import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { Terminal, ArrowLeft, Send, Clock, Folder, Activity, Network, Edit2, Check, X as XIcon, ChevronDown, ChevronRight, Copy, Monitor, Timer } from 'lucide-react';
import FileBrowser from '../components/FileBrowser';
import type { FileNode } from '../components/FileBrowser';
import ProcessBrowser from '../components/ProcessBrowser';
import type { ProcessNode } from '../components/ProcessBrowser';
import TunnelManager from '../components/TunnelManager';
import HvncViewer from '../components/HvncViewer';
import { useWebSocket, wsSend } from '../hooks/useWebSocket';
import { useNotify } from '../context/NotifyContext';
import { Box, Typography, IconButton, Button, Chip, Tabs, Tab, CircularProgress, TextField, InputAdornment, Tooltip } from '@mui/material';

interface Agent {
    id: string; platform: string; host: string; user: string;
    process: string; status: string; note: string; integrity: number; links: string[];
    last_checkin: string; sleep: string;
}

const getIntegrityProps = (level: number) => {
    if (level >= 16384) return { color: 'error', label: 'SYSTEM' };
    if (level >= 12288) return { color: 'warning', label: 'HIGH' };
    if (level >= 8192) return { color: 'info', label: 'MEDIUM' };
    return { color: 'default', label: 'LOW' };
};

interface Job {
    id: string; agent_id: string; command: string; status: string;
    created: string; sent: string; output?: string;
}

// Shlex-like tokenizer: respects single and double quoted strings
function parseCommand(input: string): { type: string; args: string[] } {
    const tokens: string[] = [];
    let cur = '';
    let inQ = false;
    let qch = '';
    for (const ch of input) {
        if (inQ) {
            if (ch === qch) inQ = false;
            else cur += ch;
        } else if (ch === '"' || ch === "'") {
            inQ = true; qch = ch;
        } else if (ch === ' ' || ch === '\t') {
            if (cur) { tokens.push(cur); cur = ''; }
        } else { cur += ch; }
    }
    if (cur) tokens.push(cur);
    return { type: tokens[0] || '', args: tokens.slice(1) };
}

function formatTime(iso: string): string {
    if (!iso) return '';
    try {
        const d = new Date(iso);
        const now = new Date();
        const diffS = Math.floor((now.getTime() - d.getTime()) / 1000);
        if (diffS < 60) return `${diffS}s ago`;
        if (diffS < 3600) return `${Math.floor(diffS / 60)}m ago`;
        if (diffS < 86400) return `${Math.floor(diffS / 3600)}h ago`;
        return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ' ' +
            d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    } catch { return iso; }
}

type TabValue = 'terminal' | 'files' | 'processes' | 'tunnels' | 'hvnc';

function LastSeenChip({ lastCheckin }: { lastCheckin: string }) {
    const [label, setLabel] = useState('');
    const [chipColor, setChipColor] = useState<'success'|'warning'|'error'|'default'>('default');
    useEffect(() => {
        if (!lastCheckin) return;
        const tick = () => {
            const s = Math.floor((Date.now() - new Date(lastCheckin).getTime()) / 1000);
            if (s < 5)        { setLabel('just now'); setChipColor('success'); }
            else if (s < 60)  { setLabel(`${s}s ago`); setChipColor('success'); }
            else if (s < 300) { setLabel(`${Math.floor(s/60)}m ago`); setChipColor('warning'); }
            else               { setLabel(`${Math.floor(s/60)}m ago`); setChipColor('error'); }
        };
        tick();
        const iv = setInterval(tick, 1000);
        return () => clearInterval(iv);
    }, [lastCheckin]);
    if (!label) return null;
    return <Chip label={label} size="small" color={chipColor} variant="outlined"
        sx={{ fontFamily: 'monospace', fontSize: '0.65rem' }} />;
}

// Collapsible output block for job results
function JobOutput({ output }: { output: string }) {
    const lines = output.split('\n');
    const isLong = lines.length > 8;
    const [collapsed, setCollapsed] = useState(isLong);

    const handleCopy = (e: React.MouseEvent) => {
        e.stopPropagation();
        navigator.clipboard.writeText(output);
    };

    return (
        <Box sx={{ mt: 0.5 }}>
            {isLong && (
                <Box
                    onClick={() => setCollapsed(c => !c)}
                    sx={{ display: 'flex', alignItems: 'center', gap: 0.5, cursor: 'pointer', color: 'text.disabled', fontSize: '0.7rem', mb: 0.5, '&:hover': { color: 'text.secondary' } }}
                >
                    {collapsed ? <ChevronRight size={12} /> : <ChevronDown size={12} />}
                    <span>{lines.length} lines</span>
                    <Tooltip title="Copy output" placement="top">
                        <IconButton size="small" onClick={handleCopy} sx={{ ml: 'auto', opacity: 0.4, '&:hover': { opacity: 1 }, p: 0.3 }}>
                            <Copy size={11} />
                        </IconButton>
                    </Tooltip>
                </Box>
            )}
            <Box sx={{
                color: 'text.secondary', fontSize: '0.78rem', whiteSpace: 'pre-wrap',
                bgcolor: 'rgba(0,0,0,0.3)', px: 1.5, py: 1, borderRadius: 1,
                border: '1px solid', borderColor: 'divider', fontFamily: 'monospace', lineHeight: 1.5,
                maxHeight: collapsed ? '6rem' : '35vh', overflowY: 'auto',
                transition: 'max-height 0.2s ease',
                ...(collapsed && { maskImage: 'linear-gradient(to bottom, black 60%, transparent 100%)', WebkitMaskImage: 'linear-gradient(to bottom, black 60%, transparent 100%)', cursor: 'pointer' }),
            }}
                onClick={collapsed ? () => setCollapsed(false) : undefined}
            >
                {output}
            </Box>
        </Box>
    );
}

export default function AgentDetails() {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const notify = useNotify();
    const [searchParams, setSearchParams] = useSearchParams();

    const [agent, setAgent] = useState<Agent | null>(null);
    const [jobs, setJobs] = useState<Job[]>([]);
    const [loading, setLoading] = useState(true);
    const [cmdInput, setCmdInput] = useState('');
    const [sending, setSending] = useState(false);
    const validTabs: TabValue[] = ['terminal', 'files', 'processes', 'tunnels', 'hvnc'];
    const tabParam = searchParams.get('tab') as TabValue | null;
    const [activeTab, setActiveTab] = useState<TabValue>(tabParam && validTabs.includes(tabParam) ? tabParam : 'terminal');
    const [history, setHistory] = useState<string[]>([]);
    const [historyIdx, setHistoryIdx] = useState(-1);
    const historyDraft = useRef('');
    const [editingNote, setEditingNote] = useState(false);
    const [noteValue, setNoteValue] = useState('');
    const [savingNote, setSavingNote] = useState(false);
    const terminalRef = useRef<HTMLDivElement>(null);
    const { lastEvent } = useWebSocket();

    // Cache for Files and Processes tabs — survives tab switches
    const [cachedFiles, setCachedFiles] = useState<FileNode[]>([]);
    const [cachedFilesPath, setCachedFilesPath] = useState('C:\\');
    const [cachedProcesses, setCachedProcesses] = useState<ProcessNode[]>([]);
    const [cachedProcessesTs, setCachedProcessesTs] = useState<number | null>(null);

    const handleFilesCacheUpdate = useCallback((files: FileNode[], path: string) => {
        setCachedFiles(files);
        setCachedFilesPath(path);
    }, []);
    const handleProcessesCacheUpdate = useCallback((procs: ProcessNode[], ts: number) => {
        setCachedProcesses(procs);
        setCachedProcessesTs(ts);
    }, []);

    const fetchData = async () => {
        try {
            const [agentData, jobsData] = await Promise.all([
                wsSend('agents.get', { id }),
                wsSend('jobs.list', { agent_id: id }),
            ]);
            setAgent(agentData);
            setNoteValue(agentData.note || '');
            setJobs(jobsData || []);
        } catch { } finally { setLoading(false); }
    };

    useEffect(() => { fetchData(); }, [id]);

    useEffect(() => {
        if (!lastEvent) return;
        const { event, payload } = lastEvent;
        if (event === 'job_complete' && payload?.agent_id === id && Array.isArray(payload?.jobs)) {
            setJobs(payload.jobs);
        } else if (event === 'agent_checkin' && payload?.id === id) {
            setAgent(payload);
        }
    }, [lastEvent, id]);

    const userScrolledUp = useRef(false);
    const handleTerminalScroll = useCallback(() => {
        const el = terminalRef.current;
        if (!el) return;
        userScrolledUp.current = el.scrollHeight - el.scrollTop - el.clientHeight > 40;
    }, []);
    useEffect(() => {
        if (terminalRef.current && !userScrolledUp.current) {
            terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
        }
    }, [jobs, activeTab]);

    const sendCommand = useCallback(async (type: string, args: string[]) => {
        await wsSend('job.create', { agent_id: id, type, args });
        // No refetch needed — job_complete event pushes updated jobs list via WS
    }, [id]);

    const handleSendCommand = async (e: React.FormEvent) => {
        e.preventDefault();
        const raw = cmdInput.trim();
        if (!raw) return;
        setSending(true);
        try {
            const { type, args } = parseCommand(raw);
            await sendCommand(type, args);
            setHistory(prev => [raw, ...prev.filter(h => h !== raw)].slice(0, 200));
            setCmdInput('');
            setHistoryIdx(-1);
            historyDraft.current = '';
        } catch (err: any) {
            notify('Failed: ' + (err.message || err), 'error');
        } finally { setSending(false); }
    };

    const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
        if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (!history.length) return;
            if (historyIdx === -1) historyDraft.current = cmdInput;
            const ni = Math.min(historyIdx + 1, history.length - 1);
            setHistoryIdx(ni); setCmdInput(history[ni]);
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (historyIdx === -1) return;
            const ni = historyIdx - 1;
            setHistoryIdx(ni); setCmdInput(ni === -1 ? historyDraft.current : history[ni]);
        }
    };

    const handleSaveNote = async () => {
        setSavingNote(true);
        try {
            await wsSend('agent.note', { agent_id: id, note: noteValue });
            setAgent(a => a ? { ...a, note: noteValue } : a);
            setEditingNote(false);
            notify('Note saved', 'success');
        } catch { notify('Failed to save note', 'error'); } finally { setSavingNote(false); }
    };

    const handleFilesCommand = useCallback(async (cmd: string) => {
        const { type, args } = parseCommand(cmd);
        await sendCommand(type, args);
    }, [sendCommand]);

    const handleProcessCommand = useCallback(async (cmd: string) => {
        const { type, args } = parseCommand(cmd);
        await sendCommand(type, args);
    }, [sendCommand]);

    // Filter out internal housekeeping jobs — must be before early returns (hooks order)
    const visibleJobs = useMemo(() => {
        const isHidden = (cmd: string) => {
            const c = cmd.trim().toLowerCase();
            return c === 'agentinfo' || c === 'ps' || c === 'ls' || c.startsWith('ls ');
        };
        return jobs.filter(j => !isHidden(j.command));
    }, [jobs]);

    if (loading && !agent) return (
        <Box sx={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center' }}>
            <CircularProgress color="secondary" />
        </Box>
    );
    if (!agent) return (
        <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%', alignItems: 'center', justifyContent: 'center' }}>
            <Typography color="text.secondary">Agent not found or disconnected.</Typography>
            <Button variant="outlined" color="primary" onClick={() => navigate('/agents')} sx={{ mt: 2 }}>Return to Agents</Button>
        </Box>
    );

    const integrity = getIntegrityProps(agent.integrity || 0);
    const statusBg = (s: string) => s === 'Complete' || s === 'Returned' ? 'rgba(184,187,38,0.15)' : s === 'Sent' || s === 'Active' ? 'rgba(250,189,47,0.15)' : 'rgba(255,255,255,0.05)';
    const statusFg = (s: string) => s === 'Complete' || s === 'Returned' ? 'success.main' : s === 'Sent' || s === 'Active' ? 'warning.main' : 'text.disabled';

    return (
        <Box sx={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 48px)', overflow: 'hidden' }}>
            {/* Compact Header */}
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1, borderBottom: 1, borderColor: 'divider', pb: 1, flexShrink: 0, flexWrap: 'wrap', gap: 1 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, minWidth: 0 }}>
                    <IconButton onClick={() => navigate('/agents')} size="small" sx={{ color: 'text.secondary', '&:hover': { color: 'text.primary', bgcolor: 'rgba(255,255,255,0.05)' } }}>
                        <ArrowLeft size={18} />
                    </IconButton>
                    <Box sx={{ minWidth: 0 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                            <Typography variant="subtitle1" fontWeight="bold" letterSpacing={0.5} noWrap>{agent.host}</Typography>
                            <Chip label={integrity.label} size="small" color={integrity.color as any} sx={{ fontSize: '0.6rem', fontWeight: 'bold', letterSpacing: 1, height: 20 }} />
                            <Chip label={agent.status || 'Init'} size="small"
                                color={agent.status === 'Active' ? 'success' : agent.status === 'Delayed' ? 'warning' : agent.status === 'Dead' ? 'error' : 'default'}
                                variant={agent.status === 'Active' ? 'filled' : 'outlined'}
                                sx={{ height: 20, fontWeight: 'bold', fontSize: '0.6rem', ...(agent.status === 'Active' && { bgcolor: 'success.main', color: '#1d2021', opacity: 0.9 }) }} />
                            {agent.last_checkin && <LastSeenChip lastCheckin={agent.last_checkin} />}
                            <Typography variant="caption" color="text.secondary" fontFamily="monospace" noWrap>
                                {agent.user} @ {agent.process} · {agent.platform}
                            </Typography>
                            {agent.sleep && (
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, color: 'text.disabled', fontSize: '0.65rem', fontFamily: 'monospace' }}>
                                    <Timer size={10} />
                                    <span>{agent.sleep}</span>
                                </Box>
                            )}
                        </Box>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.25 }}>
                            {editingNote ? (
                                <>
                                    <TextField value={noteValue} onChange={e => setNoteValue(e.target.value)} size="small"
                                        placeholder="Note..." sx={{ width: 280 }} autoFocus
                                        onKeyDown={e => { if (e.key === 'Enter') handleSaveNote(); if (e.key === 'Escape') { setNoteValue(agent.note || ''); setEditingNote(false); } }}
                                        InputProps={{ sx: { fontFamily: 'monospace', fontSize: '0.75rem', height: 28 } }} />
                                    <IconButton size="small" color="success" onClick={handleSaveNote} disabled={savingNote} sx={{ p: 0.3 }}>
                                        {savingNote ? <CircularProgress size={12} /> : <Check size={12} />}
                                    </IconButton>
                                    <IconButton size="small" onClick={() => { setNoteValue(agent.note || ''); setEditingNote(false); }} sx={{ p: 0.3 }}>
                                        <XIcon size={12} />
                                    </IconButton>
                                </>
                            ) : (
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, cursor: 'pointer' }} onClick={() => setEditingNote(true)}>
                                    <Typography variant="caption" color={agent.note ? 'text.secondary' : 'text.disabled'} fontStyle={agent.note ? 'normal' : 'italic'} fontFamily="monospace" fontSize="0.7rem">
                                        {agent.note || 'add note'}
                                    </Typography>
                                    <Edit2 size={10} style={{ opacity: 0.3 }} />
                                </Box>
                            )}
                            {agent.links?.length > 0 && (
                                <>
                                    <Box sx={{ width: 1, height: 14, bgcolor: 'divider', mx: 0.5 }} />
                                    <Typography variant="caption" color="secondary.main" fontWeight="bold" fontSize="0.65rem">PIVOTS:</Typography>
                                    {agent.links.map(lid => (
                                        <Chip key={lid} label={lid.split('-')[0]} size="small" variant="outlined"
                                            onClick={() => navigate(`/agents/${lid}`)}
                                            sx={{ height: 18, fontSize: '0.6rem', fontFamily: 'monospace', cursor: 'pointer' }} />
                                    ))}
                                </>
                            )}
                        </Box>
                    </Box>
                </Box>

                {/* Tabs */}
                <Tabs value={activeTab} onChange={(_, v) => { setActiveTab(v); if (searchParams.has('tab')) { searchParams.delete('tab'); setSearchParams(searchParams, { replace: true }); } }} indicatorColor="primary" textColor="primary"
                    sx={{ minHeight: 32, '& .MuiTab-root': { minHeight: 32, textTransform: 'none', fontSize: '0.8rem', py: 0.5, px: 1.5 } }}>
                    <Tab value="terminal" label={<Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}><Terminal size={14} />Jobs</Box>} />
                    <Tab value="files" label={<Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}><Folder size={14} />Files</Box>} />
                    <Tab value="processes" label={<Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}><Activity size={14} />Processes</Box>} />
                    <Tab value="tunnels" label={<Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}><Network size={14} />Tunnels</Box>} />
                    <Tab value="hvnc" label={<Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}><Monitor size={14} />HVNC</Box>} />
                </Tabs>
            </Box>

            {/* Tab Content */}
            {activeTab === 'files' ? (
                <FileBrowser agentId={id as string} currentJobs={jobs} onsendCommand={handleFilesCommand}
                    cachedFiles={cachedFiles} cachedPath={cachedFilesPath} onCacheUpdate={handleFilesCacheUpdate} />
            ) : activeTab === 'processes' ? (
                <ProcessBrowser agentId={id as string} currentJobs={jobs} onsendCommand={handleProcessCommand}
                    cachedProcesses={cachedProcesses} cachedTimestamp={cachedProcessesTs} onCacheUpdate={handleProcessesCacheUpdate} />
            ) : activeTab === 'tunnels' ? (
                <Box sx={{ flex: 1, overflowY: 'auto', py: 1 }}><TunnelManager agentId={id as string} /></Box>
            ) : activeTab === 'hvnc' ? (
                <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}><HvncViewer agentId={id as string} /></Box>
            ) : (
                /* Jobs Terminal */
                <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', bgcolor: '#1d2021', border: '1px solid', borderColor: 'divider', borderRadius: 1.5, overflow: 'hidden', minHeight: 0 }}>
                    {/* Chrome bar */}
                    <Box sx={{ bgcolor: 'background.paper', borderBottom: '1px solid', borderColor: 'divider', px: 1.5, py: 0.75, display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, color: 'text.secondary', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                            <Terminal size={13} /><span>fox3 ~ {agent.id.split('-')[0]}</span>
                            <Box component="span" sx={{ color: 'text.disabled', ml: 1 }}>{visibleJobs.length} jobs</Box>
                        </Box>
                        <Box sx={{ display: 'flex', gap: 0.75 }}>
                            {['error', 'warning', 'success'].map(c => (
                                <Box key={c} sx={{ width: 10, height: 10, borderRadius: '50%', bgcolor: `${c}.main`, opacity: 0.7 }} />
                            ))}
                        </Box>
                    </Box>

                    {/* Output area */}
                    <Box ref={terminalRef} onScroll={handleTerminalScroll} sx={{ flex: 1, px: 2, py: 1.5, overflowY: 'auto', fontFamily: 'monospace', fontSize: '0.8rem', display: 'flex', flexDirection: 'column', gap: 1.5, minHeight: 0 }}>
                        {visibleJobs.length ? visibleJobs.map((job, idx) => (
                            <Box key={job.id || idx} sx={{ borderLeft: '2px solid', borderColor: job.status === 'Complete' || job.status === 'Returned' ? 'success.dark' : 'primary.main', pl: 1.5, py: 0.25 }}>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, fontSize: '0.7rem', mb: 0.25 }}>
                                    <Box sx={{ display: 'flex', gap: 0.5, alignItems: 'center', color: 'text.disabled' }}>
                                        <Clock size={10} />
                                        <span>{formatTime(job.created)}</span>
                                    </Box>
                                    <Box component="span" sx={{ px: 0.75, py: 0.1, borderRadius: 0.5, fontSize: '0.55rem', fontWeight: 'bold', textTransform: 'uppercase', letterSpacing: 1, bgcolor: statusBg(job.status), color: statusFg(job.status) }}>
                                        {job.status}
                                    </Box>
                                    <Box sx={{ flex: 1 }} />
                                    <Box sx={{ display: 'flex', gap: 0.5, wordBreak: 'break-all', alignItems: 'center' }}>
                                        <span style={{ color: '#83a598', fontWeight: 'bold', fontSize: '0.75rem' }}>$</span>
                                        <span style={{ color: '#ebdbb2' }}>{job.command}</span>
                                    </Box>
                                </Box>
                                {job.output && <JobOutput output={job.output} />}
                            </Box>
                        )) : (
                            <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', flex: 1, gap: 1, opacity: 0.5 }}>
                                <Terminal size={28} />
                                <Typography variant="caption" color="text.disabled">No jobs yet. Type a command below.</Typography>
                            </Box>
                        )}
                    </Box>

                    {/* Input bar */}
                    <Box component="form" onSubmit={handleSendCommand} sx={{ bgcolor: 'rgba(0,0,0,0.25)', borderTop: '1px solid', borderColor: 'divider', px: 1.5, py: 1, flexShrink: 0, display: 'flex', gap: 1, alignItems: 'center' }}>
                        <TextField fullWidth variant="outlined" size="small" autoFocus disabled={sending}
                            placeholder={history.length ? `(${history.length} in history)` : 'command...'}
                            value={cmdInput}
                            onChange={e => { setCmdInput(e.target.value); setHistoryIdx(-1); }}
                            onKeyDown={handleKeyDown}
                            InputProps={{
                                startAdornment: <InputAdornment position="start"><Typography color="secondary.main" fontWeight="bold" fontFamily="monospace" fontSize="0.9rem">$</Typography></InputAdornment>,
                                sx: { fontFamily: 'monospace', fontSize: '0.85rem', bgcolor: 'rgba(0,0,0,0.3)', height: 36 }
                            }} />
                        <Button type="submit" variant="contained" color="primary" disabled={sending || !cmdInput.trim()}
                            sx={{ minWidth: 40, height: 36, px: 1.5 }}>
                            {sending ? <CircularProgress size={14} color="inherit" /> : <Send size={14} />}
                        </Button>
                    </Box>
                </Box>
            )}
        </Box>
    );
}
