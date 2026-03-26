import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Terminal, Cpu, RefreshCw, Search, Clock, Timer, LayoutGrid, List } from 'lucide-react';
import { Box, Button, Card, CardContent, CardActions, Typography, Grid, Chip, TextField, InputAdornment, ToggleButtonGroup, ToggleButton } from '@mui/material';
import { useWebSocket, wsSend } from '../hooks/useWebSocket';
import AgentTable from '../components/AgentTable';
import AgentContextMenu from '../components/AgentContextMenu';

export interface Agent {
    id: string; platform: string; host: string; user: string;
    process: string; status: string; alive: boolean; note: string; integrity: number;
    last_checkin: string; sleep: string;
}

export const getIntegrityProps = (level: number) => {
    if (level >= 16384) return { color: 'error', label: 'SYSTEM' };
    if (level >= 12288) return { color: 'warning', label: 'HIGH' };
    if (level >= 8192) return { color: 'info', label: 'MEDIUM' };
    return { color: 'default', label: 'LOW' };
};

export const getStatusProps = (status: string) => {
    if (status === 'Active')  return { color: 'success' as const, dot: '#b8bb26' };
    if (status === 'Delayed') return { color: 'warning' as const, dot: '#fabd2f' };
    if (status === 'Dead')    return { color: 'error'   as const, dot: '#fb4934' };
    return { color: 'default' as const, dot: '#a89984' };
};

function useLastSeen(lastCheckin: string): { label: string; color: string } {
    const [label, setLabel] = useState('');
    const [color, setColor] = useState('#a89984');
    useEffect(() => {
        if (!lastCheckin) { setLabel('never'); return; }
        const tick = () => {
            const s = Math.floor((Date.now() - new Date(lastCheckin).getTime()) / 1000);
            if (s < 5)        { setLabel('just now'); setColor('#b8bb26'); }
            else if (s < 60)  { setLabel(`${s}s ago`); setColor('#b8bb26'); }
            else if (s < 300) { setLabel(`${Math.floor(s/60)}m ago`); setColor('#fabd2f'); }
            else               { setLabel(`${Math.floor(s/60)}m ago`); setColor('#fb4934'); }
        };
        tick();
        const iv = setInterval(tick, 1000);
        return () => clearInterval(iv);
    }, [lastCheckin]);
    return { label, color };
}

function LastSeen({ lastCheckin }: { lastCheckin: string }) {
    const { label, color } = useLastSeen(lastCheckin);
    if (!label) return null;
    return (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, fontSize: '0.7rem', fontFamily: 'monospace', color }}>
            <Clock size={11} />
            <span>{label}</span>
        </Box>
    );
}

export default function Agents() {
    const navigate = useNavigate();
    const [agents, setAgents] = useState<Agent[]>([]);
    const [loading, setLoading] = useState(true);
    const [search, setSearch] = useState('');
    const [filter, setFilter] = useState<string | null>(null);
    const [viewMode, setViewMode] = useState<'card' | 'table'>(() => (localStorage.getItem('fox3_agents_view') as 'card' | 'table') || 'card');
    const { lastEvent } = useWebSocket();

    const [contextMenu, setContextMenu] = useState<{ mouseX: number; mouseY: number; agent: Agent } | null>(null);

    const handleViewChange = (_: any, v: 'card' | 'table' | null) => {
        if (v) { setViewMode(v); localStorage.setItem('fox3_agents_view', v); }
    };

    const handleContextMenu = (e: React.MouseEvent, agent: Agent) => {
        e.preventDefault();
        setContextMenu({ mouseX: e.clientX + 2, mouseY: e.clientY - 6, agent });
    };

    const fetchAgents = async () => {
        setLoading(true);
        try {
            const data = await wsSend('agents.list', {});
            setAgents(data || []);
        } catch { } finally { setLoading(false); }
    };

    useEffect(() => { fetchAgents(); }, []);
    useEffect(() => {
        if (!lastEvent) return;
        if (lastEvent.event === 'agent_checkin') {
            if (lastEvent.payload) {
                setAgents(prev => {
                    const idx = prev.findIndex(a => a.id === lastEvent.payload.id);
                    if (idx >= 0) {
                        const next = [...prev];
                        next[idx] = lastEvent.payload;
                        return next;
                    }
                    return [lastEvent.payload, ...prev];
                });
            } else {
                fetchAgents();
            }
        } else if (lastEvent.event === 'agent_removed') {
            const removedId = lastEvent.payload?.agent_id || lastEvent.payload?.id;
            if (removedId) {
                setAgents(prev => prev.filter(a => a.id !== removedId));
            } else {
                fetchAgents();
            }
        }
    }, [lastEvent]);

    const filtered = agents.filter(a => {
        const q = search.toLowerCase();
        const matchSearch = !q || a.host.toLowerCase().includes(q) || a.user.toLowerCase().includes(q) || a.process.toLowerCase().includes(q);
        const intLabel = getIntegrityProps(a.integrity || 0).label;
        const matchFilter = !filter || intLabel === filter;
        return matchSearch && matchFilter;
    });

    const counts = agents.reduce((acc, a) => {
        const l = getIntegrityProps(a.integrity || 0).label;
        acc[l] = (acc[l] || 0) + 1;
        return acc;
    }, {} as Record<string, number>);

    return (
        <Box>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3, borderBottom: 1, borderColor: 'divider', pb: 2 }}>
                <Box>
                    <Typography variant="h4" fontWeight="bold" letterSpacing={1}>Connected Agents</Typography>
                    <Typography variant="body2" color="text.secondary" mt={0.5}>
                        {agents.length} agent{agents.length !== 1 ? 's' : ''} · live updates
                    </Typography>
                </Box>
                <Button variant="outlined" color="secondary" onClick={fetchAgents}
                    startIcon={<RefreshCw className={loading ? 'animate-spin' : ''} style={{ width: 16, height: 16 }} />}>
                    Refresh
                </Button>
            </Box>

            {/* Filters */}
            {agents.length > 0 && (
                <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap', alignItems: 'center' }}>
                    <TextField
                        size="small" placeholder="Search host, user, process..."
                        value={search} onChange={e => setSearch(e.target.value)}
                        sx={{ width: 280 }}
                        InputProps={{
                            startAdornment: <InputAdornment position="start"><Search size={16} style={{ color: '#a89984' }} /></InputAdornment>,
                            sx: { fontFamily: 'monospace' }
                        }} />
                    <ToggleButtonGroup value={filter} exclusive onChange={(_, v) => setFilter(v)} size="small"
                        sx={{ '& .MuiToggleButton-root': { textTransform: 'none', fontWeight: 'bold', fontSize: '0.7rem', letterSpacing: 1, px: 1.5 } }}>
                        {['SYSTEM', 'HIGH', 'MEDIUM', 'LOW'].filter(l => counts[l] > 0).map(l => (
                            <ToggleButton key={l} value={l}
                                color={l === 'SYSTEM' ? 'error' : l === 'HIGH' ? 'warning' : l === 'MEDIUM' ? 'info' : 'standard'}>
                                {l} ({counts[l]})
                            </ToggleButton>
                        ))}
                    </ToggleButtonGroup>
                    {(search || filter) && (
                        <Button size="small" color="inherit" onClick={() => { setSearch(''); setFilter(null); }} sx={{ opacity: 0.6 }}>
                            Clear
                        </Button>
                    )}
                    <Box sx={{ ml: 'auto' }}>
                        <ToggleButtonGroup value={viewMode} exclusive onChange={handleViewChange} size="small"
                            sx={{ '& .MuiToggleButton-root': { px: 1, py: 0.5 } }}>
                            <ToggleButton value="card" title="Card view"><LayoutGrid size={16} /></ToggleButton>
                            <ToggleButton value="table" title="Table view"><List size={16} /></ToggleButton>
                        </ToggleButtonGroup>
                    </Box>
                </Box>
            )}

            {filtered.length === 0 ? (
                <Box sx={{ py: 8, textAlign: 'center', border: '2px dashed', borderColor: 'divider', borderRadius: 3 }}>
                    <Terminal style={{ width: 48, height: 48, color: '#665c54', margin: '0 auto', marginBottom: 12 }} />
                    <Typography variant="h6" color="text.secondary">
                        {agents.length === 0 ? 'No agents checking in' : 'No agents match your filter'}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" mt={1}>
                        {agents.length === 0 ? 'Waiting for initial callback...' : 'Try adjusting your search or filter'}
                    </Typography>
                </Box>
            ) : viewMode === 'table' ? (
                <AgentTable agents={filtered} onContextMenu={handleContextMenu} />
            ) : (
            <Grid container spacing={3}>
                {filtered.map((agent) => {
                    const priv = getIntegrityProps(agent.integrity || 0);
                    return (
                        <Grid size={{ xs: 12, md: 6 }} key={agent.id}>
                            <Card onContextMenu={(e) => handleContextMenu(e, agent)} sx={{
                                position: 'relative', overflow: 'hidden', border: '1px solid', borderColor: 'divider',
                                transition: 'all 0.2s', height: '100%', display: 'flex', flexDirection: 'column',
                                ':hover': { borderColor: `${priv.color}.main`, boxShadow: 4 },
                                ...(!agent.alive && { opacity: 0.45, filter: 'grayscale(0.6)' }),
                            }}>
                                <Box sx={{ position: 'absolute', top: -30, right: -30, width: 120, height: 120, bgcolor: `${priv.color}.main`, opacity: 0.08, filter: 'blur(40px)', borderRadius: '50%', zIndex: 0 }} />
                                <CardContent sx={{ position: 'relative', zIndex: 1, flexGrow: 1 }}>
                                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                                        <Box>
                                            <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', mb: 1 }}>
                                                <Chip label={agent.id.substring(0, 8)} size="small" color="primary" variant="outlined"
                                                    sx={{ fontFamily: 'monospace', fontSize: '0.7rem' }} />
                                                <Chip label={priv.label} size="small" color={priv.color as any}
                                                    sx={{ fontSize: '0.7rem', fontWeight: 'bold', letterSpacing: 1 }} />
                                            </Box>
                                            <Typography variant="h5" fontWeight="bold">{agent.host}</Typography>
                                            <Typography variant="body2" color="text.secondary">{agent.user}</Typography>
                                        </Box>
                                        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 0.5 }}>
                                            <Chip label={agent.status || 'Init'} size="small"
                                                color={getStatusProps(agent.status).color}
                                                variant={agent.status === 'Active' ? 'filled' : 'outlined'}
                                                sx={{ fontWeight: 'bold', fontSize: '0.65rem', letterSpacing: 0.5,
                                                    ...(agent.status === 'Active' && { color: '#1d2021', opacity: 0.9 }) }} />
                                            <LastSeen lastCheckin={agent.last_checkin} />
                                        </Box>
                                    </Box>
                                    <Grid container spacing={2} sx={{ mt: 1 }}>
                                        <Grid size={{ xs: 6 }}>
                                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, color: 'text.secondary' }}>
                                                <Cpu size={14} />
                                                <Typography variant="caption" noWrap>{agent.platform}</Typography>
                                            </Box>
                                        </Grid>
                                        <Grid size={{ xs: 6 }}>
                                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, color: 'text.secondary' }}>
                                                <Terminal size={14} />
                                                <Typography variant="caption" noWrap>{agent.process}</Typography>
                                            </Box>
                                        </Grid>
                                        {agent.sleep && (
                                            <Grid size={{ xs: 6 }}>
                                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, color: 'text.secondary' }}>
                                                    <Timer size={14} />
                                                    <Typography variant="caption" noWrap>{agent.sleep}</Typography>
                                                </Box>
                                            </Grid>
                                        )}
                                    </Grid>
                                    {agent.note && (
                                        <Box sx={{ mt: 2, p: 1, bgcolor: 'rgba(0,0,0,0.2)', borderRadius: 1, border: '1px solid', borderColor: 'divider' }}>
                                            <Typography variant="caption" color="text.secondary" fontFamily="monospace">{agent.note}</Typography>
                                        </Box>
                                    )}
                                </CardContent>
                                <CardActions sx={{ borderTop: '1px solid', borderColor: 'divider', p: 2, pt: 1.5, zIndex: 1 }}>
                                    <Button variant="outlined" color="primary" fullWidth onClick={() => navigate(`/agents/${agent.id}`)}>
                                        Interact
                                    </Button>
                                </CardActions>
                            </Card>
                        </Grid>
                    );
                })}
            </Grid>
            )}

            <AgentContextMenu
                agent={contextMenu?.agent || null}
                anchorPosition={contextMenu ? { mouseX: contextMenu.mouseX, mouseY: contextMenu.mouseY } : null}
                onClose={() => setContextMenu(null)}
                onAgentRemoved={(id) => setAgents(prev => prev.filter(a => a.id !== id))}
            />
        </Box>
    );
}
