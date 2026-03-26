import { useState, useEffect, useRef } from 'react';
import { RefreshCw, Crosshair, Zap, Cpu, Search, Clock, GitBranch, List, ChevronRight, ChevronDown } from 'lucide-react';
import { useNotify } from '../context/NotifyContext';
import {
    Box, Typography, Paper, Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
    Button, CircularProgress, Menu, MenuItem, ListItemIcon, ListItemText, Divider,
    Dialog, DialogTitle, DialogContent, DialogActions, TextField, InputAdornment,
    ToggleButtonGroup, ToggleButton, IconButton
} from '@mui/material';

export interface ProcessNode {
    pid: number; ppid: number; executable: string;
    architecture: string; session: number; user: string;
}

interface ProcessBrowserProps {
    agentId: string;
    onsendCommand: (cmd: string) => void;
    currentJobs: any[];
    cachedProcesses: ProcessNode[];
    cachedTimestamp: number | null;
    onCacheUpdate: (procs: ProcessNode[], ts: number) => void;
}

export function parsePsOutput(raw: string): ProcessNode[] {
    try {
        const data = JSON.parse(raw);
        if (Array.isArray(data)) {
            const procs: ProcessNode[] = data.map((p: any) => ({
                pid: p.pid || 0, ppid: p.ppid || 0, executable: p.name || '',
                architecture: p.arch || 'N/A', session: p.session_id ?? -1,
                user: p.session || '',
            }));
            procs.sort((a, b) => a.pid - b.pid);
            return procs;
        }
    } catch { /* not JSON — raw text fallback */ }
    const lines = raw.split('\n').map(l => l.trim()).filter(Boolean);
    const procs: ProcessNode[] = [];
    for (const line of lines) {
        const p = line.split(/\s+/);
        if (p.length >= 3) procs.push({ pid: +p[0], ppid: +p[1], executable: p[2], architecture: 'N/A', session: -1, user: '' });
    }
    procs.sort((a, b) => a.pid - b.pid);
    return procs;
}

interface TreeNode extends ProcessNode { depth: number; hasChildren: boolean; }

function buildTree(procs: ProcessNode[], collapsed: Set<number>): TreeNode[] {
    const pidSet = new Set(procs.map(p => p.pid));
    const childMap = new Map<number, ProcessNode[]>();
    const roots: ProcessNode[] = [];
    for (const p of procs) {
        if (!pidSet.has(p.ppid) || p.ppid === 0) roots.push(p);
        else {
            if (!childMap.has(p.ppid)) childMap.set(p.ppid, []);
            childMap.get(p.ppid)!.push(p);
        }
    }
    const result: TreeNode[] = [];
    function walk(nodes: ProcessNode[], depth: number) {
        for (const n of nodes) {
            const kids = childMap.get(n.pid) || [];
            result.push({ ...n, depth, hasChildren: kids.length > 0 });
            if (kids.length > 0 && !collapsed.has(n.pid)) {
                walk(kids, depth + 1);
            }
        }
    }
    walk(roots, 0);
    return result;
}

function formatAge(ts: number): string {
    const s = Math.floor((Date.now() - ts) / 1000);
    if (s < 5) return 'just now';
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    return `${Math.floor(s / 3600)}h ago`;
}

export default function ProcessBrowser({ agentId: _agentId, onsendCommand, currentJobs, cachedProcesses, cachedTimestamp, onCacheUpdate }: ProcessBrowserProps) {
    const notify = useNotify();
    const [processes, setProcesses] = useState<ProcessNode[]>(cachedProcesses || []);
    const [loading, setLoading] = useState(false);
    const [pendingSince, setPendingSince] = useState<number>(0);
    const [lastParsedId, setLastParsedId] = useState<string | null>(null);
    const [search, setSearch] = useState('');
    const [contextMenu, setContextMenu] = useState<{ mouseX: number; mouseY: number; pid: number } | null>(null);
    const [injectOpen, setInjectOpen] = useState(false);
    const [injectPid, setInjectPid] = useState(0);
    const [injectPayload, setInjectPayload] = useState('');
    const [confirmOpen, setConfirmOpen] = useState(false);
    const [confirmAction, setConfirmAction] = useState<{ type: 'kill' | 'token'; pid: number } | null>(null);
    const [fetchedAt, setFetchedAt] = useState<number | null>(cachedTimestamp);
    const [, setTick] = useState(0);
    const didInitialFetch = useRef(false);
    const [viewMode, setViewMode] = useState<'flat' | 'tree'>('flat');
    const [collapsed, setCollapsed] = useState<Set<number>>(new Set());

    const toggleCollapse = (pid: number) => {
        setCollapsed(prev => {
            const next = new Set(prev);
            next.has(pid) ? next.delete(pid) : next.add(pid);
            return next;
        });
    };

    // Only fetch on first mount if no cached data
    useEffect(() => {
        if (didInitialFetch.current) return;
        didInitialFetch.current = true;
        if (cachedProcesses.length === 0) {
            refreshProcesses();
        }
    }, []);

    // Tick the age display every second
    useEffect(() => {
        if (!fetchedAt) return;
        const iv = setInterval(() => setTick(t => t + 1), 1000);
        return () => clearInterval(iv);
    }, [fetchedAt]);

    // Watch currentJobs for completed ps results
    useEffect(() => {
        if (!pendingSince || !currentJobs) return;
        const psJobs = currentJobs
            .filter((j: any) => j.command.trim() === 'ps' && j.id !== lastParsedId)
            .sort((a: any, b: any) => new Date(b.created).getTime() - new Date(a.created).getTime());
        const latest = psJobs[0];
        if (latest && (latest.status === 'Complete' || latest.status === 'Returned') && latest.output) {
            const parsed = parsePsOutput(latest.output);
            const now = Date.now();
            setProcesses(parsed);
            setFetchedAt(now);
            onCacheUpdate(parsed, now);
            setLoading(false);
            setPendingSince(0);
            setLastParsedId(latest.id);
        }
    }, [currentJobs, pendingSince]);

    const refreshProcesses = () => {
        setLoading(true);
        setProcesses([]);
        setPendingSince(Date.now());
        onsendCommand('ps');
    };

    const openContext = (e: React.MouseEvent, pid: number) => {
        e.preventDefault();
        setContextMenu({ mouseX: e.clientX + 2, mouseY: e.clientY - 6, pid });
    };

    const closeContext = () => setContextMenu(null);

    const openInject = (pid: number) => { setInjectPid(pid); setInjectPayload(''); setInjectOpen(true); closeContext(); };
    const confirmInject = () => {
        if (!injectPayload.trim()) { notify('Shellcode payload is required', 'warning'); return; }
        onsendCommand(`shellcode ${injectPayload.trim()} remote ${injectPid}`);
        notify(`Shellcode queued for injection into PID ${injectPid}`, 'info');
        setInjectOpen(false);
    };

    const openConfirm = (type: 'kill' | 'token', pid: number) => { setConfirmAction({ type, pid }); setConfirmOpen(true); closeContext(); };
    const doConfirmAction = () => {
        if (!confirmAction) return;
        if (confirmAction.type === 'kill') {
            onsendCommand(`killprocess ${confirmAction.pid}`);
            notify(`Kill signal sent to PID ${confirmAction.pid}`, 'warning');
        } else {
            onsendCommand(`token steal ${confirmAction.pid}`);
            notify(`Token steal queued for PID ${confirmAction.pid}`, 'info');
        }
        setConfirmOpen(false);
    };

    const filtered = processes.filter(p =>
        !search || p.executable.toLowerCase().includes(search.toLowerCase()) ||
        String(p.pid).includes(search) || p.user.toLowerCase().includes(search.toLowerCase())
    );

    return (
        <Box sx={{ flex: 1, bgcolor: '#1d2021', borderRadius: 2, border: '1px solid', borderColor: 'divider', display: 'flex', flexDirection: 'column', overflow: 'hidden', boxShadow: 10 }}>
            {/* Toolbar */}
            <Box sx={{ bgcolor: 'background.paper', borderBottom: '1px solid', borderColor: 'divider', p: 1.5, display: 'flex', alignItems: 'center', gap: 2, flexShrink: 0 }}>
                <Button variant="contained" color="primary" size="small" onClick={refreshProcesses} disabled={loading}
                    startIcon={loading ? <CircularProgress size={14} color="inherit" /> : <RefreshCw size={14} />} sx={{ whiteSpace: 'nowrap' }}>
                    Refresh Processes
                </Button>
                <ToggleButtonGroup value={viewMode} exclusive onChange={(_, v) => { if (v) setViewMode(v); }} size="small"
                    sx={{ '& .MuiToggleButton-root': { px: 0.75, py: 0.5 } }}>
                    <ToggleButton value="flat" title="Flat list"><List size={14} /></ToggleButton>
                    <ToggleButton value="tree" title="Process tree"><GitBranch size={14} /></ToggleButton>
                </ToggleButtonGroup>
                <TextField size="small" placeholder="Filter by name, PID, user..." value={search} onChange={e => setSearch(e.target.value)}
                    sx={{ flex: 1, maxWidth: 300 }}
                    InputProps={{ startAdornment: <InputAdornment position="start"><Search size={14} style={{ color: '#a89984' }} /></InputAdornment>, sx: { fontFamily: 'monospace' } }} />
                <Box sx={{ ml: 'auto', display: 'flex', alignItems: 'center', gap: 1 }}>
                    {fetchedAt && (
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, color: 'text.disabled', fontSize: '0.7rem', fontFamily: 'monospace' }}>
                            <Clock size={11} />
                            <span>Fetched {formatAge(fetchedAt)}</span>
                        </Box>
                    )}
                    <Typography variant="body2" color="text.secondary" fontFamily="monospace">
                        {filtered.length}/{processes.length} processes
                    </Typography>
                </Box>
            </Box>

            {/* List */}
            <Box sx={{ flex: 1, overflowY: 'auto', p: 2, bgcolor: 'rgba(0,0,0,0.2)' }}>
                {loading && !processes.length ? (
                    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'text.secondary' }}>
                        <CircularProgress color="primary" sx={{ mb: 2 }} />
                        <Typography>Querying running processes...</Typography>
                        <Typography variant="caption" mt={1}>Waiting for agent to return ps results.</Typography>
                    </Box>
                ) : !filtered.length ? (
                    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'text.secondary' }}>
                        <Cpu size={48} style={{ opacity: 0.2, marginBottom: 12 }} />
                        <Typography>{processes.length ? 'No processes match your filter' : 'No processes found'}</Typography>
                    </Box>
                ) : (
                    <TableContainer component={Paper} elevation={0} sx={{ bgcolor: 'transparent', border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
                        <Table size="small" stickyHeader>
                            <TableHead>
                                <TableRow>
                                    {(viewMode === 'tree' ? ['PID', 'PPID', 'Executable', 'Arch', 'Sess', 'User'] : ['PID', 'PPID', 'Executable', 'Arch', 'Sess', 'User']).map(h => (
                                        <TableCell key={h} sx={{ bgcolor: 'background.paper', fontWeight: 'bold', color: 'text.secondary', textTransform: 'uppercase', fontSize: '0.7rem' }}>{h}</TableCell>
                                    ))}
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {viewMode === 'tree' ? (
                                    buildTree(filtered, collapsed).map((proc, idx) => (
                                        <TableRow key={idx} hover onContextMenu={e => openContext(e, proc.pid)}
                                            sx={{ cursor: 'context-menu', '&:last-child td': { border: 0 } }}>
                                            <TableCell><Typography variant="body2" color="primary.light" fontFamily="monospace" fontWeight="medium">{proc.pid}</Typography></TableCell>
                                            <TableCell><Typography variant="body2" color="text.secondary" fontFamily="monospace">{proc.ppid}</Typography></TableCell>
                                            <TableCell>
                                                <Box sx={{ display: 'flex', alignItems: 'center', pl: proc.depth * 3 }}>
                                                    {proc.hasChildren ? (
                                                        <IconButton size="small" onClick={() => toggleCollapse(proc.pid)} sx={{ p: 0, mr: 0.5, color: 'text.disabled' }}>
                                                            {collapsed.has(proc.pid) ? <ChevronRight size={14} /> : <ChevronDown size={14} />}
                                                        </IconButton>
                                                    ) : (
                                                        <Box sx={{ width: 22, mr: 0.5 }} />
                                                    )}
                                                    {proc.depth > 0 && (
                                                        <Box sx={{ borderLeft: '1px solid', borderBottom: '1px solid', borderColor: 'divider', width: 10, height: 10, mr: 0.5, flexShrink: 0, mb: '5px' }} />
                                                    )}
                                                    <Cpu size={14} color="#a89984" style={{ flexShrink: 0, marginRight: 6 }} />
                                                    <Typography variant="body2" noWrap>{proc.executable}</Typography>
                                                </Box>
                                            </TableCell>
                                            <TableCell><Typography variant="body2" color="text.secondary" fontFamily="monospace" fontSize="0.75rem">{proc.architecture}</Typography></TableCell>
                                            <TableCell><Typography variant="body2" color="text.secondary">{proc.session === -1 ? '—' : proc.session}</Typography></TableCell>
                                            <TableCell><Typography variant="body2" color="text.secondary" fontFamily="monospace">{proc.user}</Typography></TableCell>
                                        </TableRow>
                                    ))
                                ) : (
                                    filtered.map((proc, idx) => (
                                        <TableRow key={idx} hover onContextMenu={e => openContext(e, proc.pid)}
                                            sx={{ cursor: 'context-menu', '&:last-child td': { border: 0 } }}>
                                            <TableCell><Typography variant="body2" color="primary.light" fontFamily="monospace" fontWeight="medium">{proc.pid}</Typography></TableCell>
                                            <TableCell><Typography variant="body2" color="text.secondary" fontFamily="monospace">{proc.ppid}</Typography></TableCell>
                                            <TableCell>
                                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                                    <Cpu size={14} color="#a89984" />
                                                    <Typography variant="body2">{proc.executable}</Typography>
                                                </Box>
                                            </TableCell>
                                            <TableCell><Typography variant="body2" color="text.secondary" fontFamily="monospace" fontSize="0.75rem">{proc.architecture}</Typography></TableCell>
                                            <TableCell><Typography variant="body2" color="text.secondary">{proc.session === -1 ? '—' : proc.session}</Typography></TableCell>
                                            <TableCell><Typography variant="body2" color="text.secondary" fontFamily="monospace">{proc.user}</Typography></TableCell>
                                        </TableRow>
                                    ))
                                )}
                            </TableBody>
                        </Table>
                    </TableContainer>
                )}
            </Box>

            {/* Context Menu */}
            <Menu open={!!contextMenu} onClose={closeContext} anchorReference="anchorPosition"
                anchorPosition={contextMenu ? { top: contextMenu.mouseY, left: contextMenu.mouseX } : undefined}
                PaperProps={{ sx: { bgcolor: 'background.paper', border: '1px solid', borderColor: 'divider', minWidth: 200, backgroundImage: 'none' } }}>
                <Box sx={{ px: 2, py: 1, borderBottom: '1px solid', borderColor: 'divider', mb: 1, display: 'flex', justifyContent: 'space-between' }}>
                    <Typography variant="caption" color="text.secondary" fontWeight="bold" textTransform="uppercase">PID:</Typography>
                    <Typography variant="caption" color="primary.main" fontFamily="monospace" fontWeight="bold">{contextMenu?.pid}</Typography>
                </Box>
                <MenuItem onClick={() => openInject(contextMenu!.pid)}>
                    <ListItemIcon><Zap size={16} color="#83a598" /></ListItemIcon>
                    <ListItemText primary="Inject Shellcode" primaryTypographyProps={{ variant: 'body2' }} />
                </MenuItem>
                <MenuItem onClick={() => openConfirm('token', contextMenu!.pid)}>
                    <ListItemIcon><Crosshair size={16} color="#d3869b" /></ListItemIcon>
                    <ListItemText primary="Steal Token" primaryTypographyProps={{ variant: 'body2' }} />
                </MenuItem>
                <Divider sx={{ my: 0.5, borderColor: 'divider' }} />
                <MenuItem onClick={() => openConfirm('kill', contextMenu!.pid)} sx={{ color: 'error.main', '&:hover': { bgcolor: 'error.main', color: 'white' } }}>
                    <ListItemIcon><Typography variant="body1" fontWeight="bold" color="inherit" sx={{ lineHeight: 1 }}>×</Typography></ListItemIcon>
                    <ListItemText primary="Kill Process" primaryTypographyProps={{ variant: 'body2' }} />
                </MenuItem>
            </Menu>

            {/* Shellcode Inject Dialog */}
            <Dialog open={injectOpen} onClose={() => setInjectOpen(false)} maxWidth="sm" fullWidth>
                <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                    <Zap size={20} color="#83a598" />
                    <Typography fontWeight="bold">Inject Shellcode into PID {injectPid}</Typography>
                </DialogTitle>
                <DialogContent>
                    <Typography variant="body2" color="text.secondary" mb={2}>
                        Paste base64-encoded shellcode or raw payload. The agent will allocate and execute it inside the target process.
                    </Typography>
                    <TextField fullWidth multiline rows={4} label="Base64 Shellcode" placeholder="/EiD5PDowAAAAEFRQVBSUVZIMdJlSIsMJUAAAABIi0kQSIt..." value={injectPayload}
                        onChange={e => setInjectPayload(e.target.value)} size="small"
                        InputProps={{ sx: { fontFamily: 'monospace', fontSize: '0.78rem' } }}
                        error={injectPayload.trim() !== '' && !/^[A-Za-z0-9+/]+=*$/.test(injectPayload.trim())}
                        helperText={injectPayload.trim() && !/^[A-Za-z0-9+/]+=*$/.test(injectPayload.trim()) ? 'Payload does not look like valid base64' : ''} />
                </DialogContent>
                <DialogActions sx={{ p: 2 }}>
                    <Button onClick={() => setInjectOpen(false)} color="inherit">Cancel</Button>
                    <Button onClick={confirmInject} variant="contained" color="info" disabled={!injectPayload.trim()}
                        startIcon={<Zap size={14} />}>Inject</Button>
                </DialogActions>
            </Dialog>

            {/* Kill / Token Confirm Dialog */}
            <Dialog open={confirmOpen} onClose={() => setConfirmOpen(false)} maxWidth="xs" fullWidth>
                <DialogTitle>
                    <Typography fontWeight="bold">
                        {confirmAction?.type === 'kill' ? `Kill PID ${confirmAction?.pid}?` : `Steal token from PID ${confirmAction?.pid}?`}
                    </Typography>
                </DialogTitle>
                <DialogContent>
                    <Typography variant="body2" color="text.secondary">
                        {confirmAction?.type === 'kill'
                            ? 'This will send a termination signal to the process. This action cannot be undone.'
                            : 'This will attempt to duplicate and impersonate the token of the target process.'}
                    </Typography>
                </DialogContent>
                <DialogActions sx={{ p: 2 }}>
                    <Button onClick={() => setConfirmOpen(false)} color="inherit">Cancel</Button>
                    <Button onClick={doConfirmAction} variant="contained" color={confirmAction?.type === 'kill' ? 'error' : 'warning'}>
                        {confirmAction?.type === 'kill' ? 'Kill' : 'Steal Token'}
                    </Button>
                </DialogActions>
            </Dialog>
        </Box>
    );
}
