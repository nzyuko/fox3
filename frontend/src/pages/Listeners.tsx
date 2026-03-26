import { useState, useEffect } from 'react';
import { Play, Square, Trash2, RefreshCw, Plus, X } from 'lucide-react';
import { useWebSocket, wsSend } from '../hooks/useWebSocket';
import { useNotify } from '../context/NotifyContext';
import {
    Box, Button, Typography, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper, Chip, IconButton,
    Dialog, DialogTitle, DialogContent, DialogActions, TextField, MenuItem, CircularProgress
} from '@mui/material';

interface Listener { id: string; name: string; protocol: string; bind_addr: string; status: string; description: string; }

const PROTOCOLS = ['https', 'wss', 'doh', 'dns', 'tcp'];

const PROTO_COLORS: Record<string, any> = { https: 'primary', wss: 'secondary', doh: 'warning', dns: 'info', tcp: 'success' };

export default function Listeners() {
    const notify = useNotify();
    const { lastEvent } = useWebSocket();
    const [listeners, setListeners] = useState<Listener[]>([]);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);
    const [protocol, setProtocol] = useState('https');
    const [options, setOptions] = useState<Record<string, string>>({});
    const [creating, setCreating] = useState(false);
    const [delConfirm, setDelConfirm] = useState<{ open: boolean; id: string; name: string }>({ open: false, id: '', name: '' });

    const fetchListeners = async () => {
        setLoading(true);
        try { const data = await wsSend('listeners.list', {}); setListeners(data || []); }
        catch { } finally { setLoading(false); }
    };

    const fetchOptions = async (proto: string) => {
        try { const data = await wsSend('listeners.options', { protocol: proto }); setOptions(data || {}); }
        catch { setOptions({ Name: `New ${proto.toUpperCase()} Listener`, Protocol: proto, Interface: '0.0.0.0', Port: '443' }); }
    };

    useEffect(() => { fetchListeners(); }, []);
    useEffect(() => {
        if (!lastEvent) return;
        if (lastEvent.event === 'listener_start' || lastEvent.event === 'listener_stop') fetchListeners();
    }, [lastEvent]);
    useEffect(() => { if (showModal) fetchOptions(protocol); }, [showModal, protocol]);

    const handleAction = async (id: string, action: 'start' | 'stop') => {
        try {
            await wsSend(`listener.${action}`, { id });
            // Event-driven: listener_start/listener_stop event triggers fetchListeners
        } catch { notify(`Failed to ${action} listener`, 'error'); }
    };

    const handleDelete = async () => {
        try {
            await wsSend('listener.delete', { id: delConfirm.id });
            notify('Listener deleted', 'success');
            // Event-driven: listener_stop event triggers fetchListeners
        } catch { notify('Failed to delete listener', 'error'); }
        finally { setDelConfirm({ open: false, id: '', name: '' }); }
    };

    const handleCreate = async (e: React.FormEvent) => {
        e.preventDefault();
        setCreating(true);
        try {
            await wsSend('listener.create', { ...options, Protocol: protocol });
            notify('Listener created', 'success');
            setShowModal(false);
            // Event-driven: listener_start event triggers fetchListeners
        } catch (err: any) { notify('Failed: ' + (err.message || err), 'error'); }
        finally { setCreating(false); }
    };

    return (
        <Box>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4, borderBottom: 1, borderColor: 'divider', pb: 2 }}>
                <Box>
                    <Typography variant="h4" fontWeight="bold" letterSpacing={1}>Active Listeners</Typography>
                    <Typography variant="body2" color="text.secondary" mt={0.5}>Manage C2 endpoints</Typography>
                </Box>
                <Box sx={{ display: 'flex', gap: 2 }}>
                    <Button variant="outlined" color="secondary" onClick={fetchListeners}
                        startIcon={<RefreshCw className={loading ? 'animate-spin' : ''} style={{ width: 16, height: 16 }} />}>Refresh</Button>
                    <Button variant="contained" color="primary" onClick={() => setShowModal(true)}
                        startIcon={<Plus style={{ width: 16, height: 16 }} />}>Create Listener</Button>
                </Box>
            </Box>

            <TableContainer component={Paper} variant="outlined" sx={{ bgcolor: 'background.paper', borderRadius: 2 }}>
                <Table>
                    <TableHead>
                        <TableRow>
                            {['Name', 'Protocol', 'Interface', 'Status', ''].map(h => (
                                <TableCell key={h} align={h === '' ? 'right' : 'left'}>{h}</TableCell>
                            ))}
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {!listeners.length ? (
                            <TableRow><TableCell colSpan={5} align="center" sx={{ py: 6, color: 'text.secondary', fontStyle: 'italic' }}>No listeners configured.</TableCell></TableRow>
                        ) : listeners.map(l => (
                            <TableRow key={l.id} hover sx={{ '&:last-child td': { border: 0 } }}>
                                <TableCell sx={{ fontWeight: 'medium' }}>{l.name}</TableCell>
                                <TableCell>
                                    <Chip label={l.protocol.toUpperCase()} size="small" variant="outlined"
                                        color={PROTO_COLORS[l.protocol.toLowerCase()] || 'default'}
                                        sx={{ fontFamily: 'monospace', fontWeight: 'bold', fontSize: '0.7rem' }} />
                                </TableCell>
                                <TableCell><Typography variant="body2" fontFamily="monospace" color="text.secondary">{l.bind_addr}</Typography></TableCell>
                                <TableCell>
                                    <Chip label={l.status} size="small"
                                        color={l.status.toLowerCase() === 'active' ? 'success' : 'default'}
                                        variant={l.status.toLowerCase() === 'active' ? 'filled' : 'outlined'}
                                        sx={{ fontWeight: 'bold', ...(l.status.toLowerCase() !== 'active' && { color: 'text.secondary' }) }} />
                                </TableCell>
                                <TableCell align="right">
                                    {l.status.toLowerCase() !== 'active' ? (
                                        <IconButton size="small" color="success" onClick={() => handleAction(l.id, 'start')} title="Start"><Play style={{ width: 16, height: 16 }} /></IconButton>
                                    ) : (
                                        <IconButton size="small" color="warning" onClick={() => handleAction(l.id, 'stop')} title="Stop"><Square style={{ width: 16, height: 16, fill: 'currentColor' }} /></IconButton>
                                    )}
                                    <IconButton size="small" color="error" onClick={() => setDelConfirm({ open: true, id: l.id, name: l.name })} title="Delete" sx={{ ml: 1 }}>
                                        <Trash2 style={{ width: 16, height: 16 }} />
                                    </IconButton>
                                </TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </TableContainer>

            {/* Create Modal */}
            <Dialog open={showModal} onClose={() => setShowModal(false)} maxWidth="sm" fullWidth>
                <DialogTitle sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: 1, borderColor: 'divider', pb: 2 }}>
                    <Typography variant="h6" fontWeight="bold">Create Listener</Typography>
                    <IconButton size="small" onClick={() => setShowModal(false)}><X style={{ width: 18, height: 18 }} /></IconButton>
                </DialogTitle>
                <DialogContent sx={{ mt: 2 }}>
                    <form id="create-listener-form" onSubmit={handleCreate}>
                        <TextField select fullWidth label="Protocol" value={protocol} onChange={e => setProtocol(e.target.value)} margin="normal" size="small">
                            {PROTOCOLS.map(p => <MenuItem key={p} value={p} sx={{ textTransform: 'uppercase', fontFamily: 'monospace' }}>{p.toUpperCase()}</MenuItem>)}
                        </TextField>
                        <Box sx={{ mt: 2, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
                            {Object.entries(options).map(([k, v]) => {
                                if (k === 'Protocol') return null;
                                return (
                                    <TextField key={k} label={k} value={v} size="small" fullWidth
                                        onChange={e => setOptions({ ...options, [k]: e.target.value })}
                                        sx={{ gridColumn: (k === 'Description' || k === 'Name') ? 'span 2' : 'span 1' }} />
                                );
                            })}
                        </Box>
                    </form>
                </DialogContent>
                <DialogActions sx={{ p: 2.5, borderTop: 1, borderColor: 'divider' }}>
                    <Button onClick={() => setShowModal(false)} color="inherit">Cancel</Button>
                    <Button type="submit" form="create-listener-form" variant="contained" color="primary" disabled={creating}
                        startIcon={creating ? <CircularProgress size={14} color="inherit" /> : <Plus size={14} />}>
                        {creating ? 'Creating...' : 'Launch Listener'}
                    </Button>
                </DialogActions>
            </Dialog>

            {/* Delete Confirm */}
            <Dialog open={delConfirm.open} onClose={() => setDelConfirm({ open: false, id: '', name: '' })} maxWidth="xs" fullWidth>
                <DialogTitle><Typography fontWeight="bold">Delete Listener</Typography></DialogTitle>
                <DialogContent>
                    <Typography variant="body2" color="text.secondary">
                        Delete <strong style={{ color: '#ebdbb2' }}>{delConfirm.name}</strong>? This cannot be undone.
                    </Typography>
                </DialogContent>
                <DialogActions sx={{ p: 2 }}>
                    <Button onClick={() => setDelConfirm({ open: false, id: '', name: '' })} color="inherit">Cancel</Button>
                    <Button onClick={handleDelete} variant="contained" color="error">Delete</Button>
                </DialogActions>
            </Dialog>
        </Box>
    );
}
