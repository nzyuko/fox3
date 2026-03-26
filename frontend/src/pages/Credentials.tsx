import { useState, useEffect } from 'react';
import { useWebSocket, wsSend } from '../hooks/useWebSocket';
import { useNotify } from '../context/NotifyContext';
import {
    Box, Button, Typography, Table, TableBody, TableCell, TableContainer, TableHead,
    TableRow, Paper, IconButton, Chip, Dialog, DialogTitle, DialogContent, DialogActions,
    TextField, Tooltip, InputAdornment, Divider, Collapse
} from '@mui/material';
import {
    Key, Plus, Trash2, RefreshCw, Copy, Eye, EyeOff, X, ShieldAlert, ChevronDown, ChevronUp
} from 'lucide-react';

interface Credential {
    id: string;
    domain: string;
    username: string;
    password?: string;
    hash?: string;
    source: string;
    agent_id: string;
    created: string;
}

interface ConfirmState { open: boolean; id: string; username: string; }

const emptyForm = { domain: '', username: '', password: '', hash: '', source: '', agent_id: '' };

export default function Credentials() {
    const notify = useNotify();
    const { lastEvent: _lastEvent } = useWebSocket();

    const [credentials, setCredentials] = useState<Credential[]>([]);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);
    const [formData, setFormData] = useState(emptyForm);
    const [creating, setCreating] = useState(false);
    const [confirmState, setConfirmState] = useState<ConfirmState>({ open: false, id: '', username: '' });
    const [visiblePasswords, setVisiblePasswords] = useState<Set<string>>(new Set());
    const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

    const fetchCredentials = async () => {
        setLoading(true);
        try {
            const data = await wsSend('credentials.list', {});
            setCredentials(data || []);
        } catch {
            notify('Failed to fetch credentials', 'error');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchCredentials(); }, []);

    // No auto-refresh on agent_checkin — credentials rarely change per beacon.
    // User can manually refresh; credential.create/delete update local state directly.

    const handleDelete = (id: string, username: string) => {
        setConfirmState({ open: true, id, username });
    };

    const confirmDelete = async () => {
        try {
            await wsSend('credential.delete', { id: confirmState.id });
            notify('Credential deleted', 'success');
            setCredentials(prev => prev.filter(c => c.id !== confirmState.id));
        } catch {
            notify('Failed to delete credential', 'error');
        } finally {
            setConfirmState({ open: false, id: '', username: '' });
        }
    };

    const handleCreate = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!formData.username.trim()) return;
        setCreating(true);
        try {
            const newCred = await wsSend('credential.create', formData);
            notify('Credential saved', 'success');
            setShowModal(false);
            setFormData(emptyForm);
            setCredentials(prev => [newCred, ...prev]);
        } catch (err: any) {
            notify('Failed: ' + (err.message || err), 'error');
        } finally {
            setCreating(false);
        }
    };

    const copyToClipboard = (text: string, label: string) => {
        navigator.clipboard.writeText(text)
            .then(() => notify(`${label} copied`, 'success'))
            .catch(() => notify('Clipboard access denied', 'warning'));
    };

    const togglePassword = (id: string) => setVisiblePasswords(prev => {
        const next = new Set(prev);
        next.has(id) ? next.delete(id) : next.add(id);
        return next;
    });

    const toggleRow = (id: string) => setExpandedRows(prev => {
        const next = new Set(prev);
        next.has(id) ? next.delete(id) : next.add(id);
        return next;
    });

    const formatAgent = (id: string) =>
        id === '00000000-0000-0000-0000-000000000000' ? 'Manual' : id.split('-')[0].toUpperCase();

    return (
        <Box>
            {/* Header */}
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4, borderBottom: 1, borderColor: 'divider', pb: 2 }}>
                <Box>
                    <Typography variant="h4" fontWeight="bold" color="text.primary" letterSpacing={1}>Credential Store</Typography>
                    <Typography variant="body2" color="text.secondary" mt={0.5}>
                        {credentials.length} credential{credentials.length !== 1 ? 's' : ''} · auto-refreshes on agent check-in
                    </Typography>
                </Box>
                <Box sx={{ display: 'flex', gap: 2 }}>
                    <Button variant="outlined" color="secondary" onClick={fetchCredentials}
                        startIcon={<RefreshCw className={loading ? 'animate-spin' : ''} style={{ width: 16, height: 16 }} />}>
                        Refresh
                    </Button>
                    <Button variant="contained" color="primary" onClick={() => setShowModal(true)}
                        startIcon={<Plus style={{ width: 16, height: 16 }} />}>
                        Add Credential
                    </Button>
                </Box>
            </Box>

            {/* Table */}
            <TableContainer component={Paper} variant="outlined" sx={{ bgcolor: 'background.paper', borderRadius: 2 }}>
                <Table>
                    <TableHead>
                        <TableRow>
                            <TableCell sx={{ width: 32, pr: 0 }} />
                            <TableCell>Domain</TableCell>
                            <TableCell>Username</TableCell>
                            <TableCell>Password</TableCell>
                            <TableCell>Hash</TableCell>
                            <TableCell>Source</TableCell>
                            <TableCell>Agent</TableCell>
                            <TableCell align="right">Actions</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {credentials.length === 0 ? (
                            <TableRow>
                                <TableCell colSpan={8} align="center" sx={{ py: 8 }}>
                                    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1, color: 'text.disabled' }}>
                                        <Key style={{ width: 40, height: 40, opacity: 0.3 }} />
                                        <Typography variant="body2">No harvested credentials in the datastore</Typography>
                                        <Typography variant="caption">Credentials appear here from agent jobs or manual entry</Typography>
                                    </Box>
                                </TableCell>
                            </TableRow>
                        ) : credentials.map((c) => {
                            const expanded = expandedRows.has(c.id);
                            const pwVisible = visiblePasswords.has(c.id);
                            const hasHash = !!(c.hash?.trim());
                            return (
                                <>
                                    <TableRow key={c.id} hover sx={{ '&:last-child td': { border: 0 } }}>
                                        <TableCell sx={{ width: 32, pr: 0 }}>
                                            {hasHash && (
                                                <IconButton size="small" onClick={() => toggleRow(c.id)}
                                                    sx={{ color: 'text.disabled', '&:hover': { color: 'text.primary' } }}>
                                                    {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                                                </IconButton>
                                            )}
                                        </TableCell>
                                        <TableCell>
                                            <Typography variant="body2" color="text.secondary" fontFamily="monospace">
                                                {c.domain || '\u2014'}
                                            </Typography>
                                        </TableCell>
                                        <TableCell>
                                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                                <Typography variant="body2" fontWeight="bold">{c.username}</Typography>
                                                <Tooltip title="Copy username">
                                                    <IconButton size="small" sx={{ opacity: 0.3, '&:hover': { opacity: 1 } }}
                                                        onClick={() => copyToClipboard(c.username, 'Username')}>
                                                        <Copy size={12} />
                                                    </IconButton>
                                                </Tooltip>
                                            </Box>
                                        </TableCell>
                                        <TableCell>
                                            {c.password ? (
                                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                                    <Typography variant="body2" fontFamily="monospace" color="secondary.main" sx={{ fontSize: '0.8rem' }}>
                                                        {pwVisible ? c.password : '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022'}
                                                    </Typography>
                                                    <Tooltip title={pwVisible ? 'Hide' : 'Show'}>
                                                        <IconButton size="small" sx={{ opacity: 0.4, '&:hover': { opacity: 1 } }} onClick={() => togglePassword(c.id)}>
                                                            {pwVisible ? <EyeOff size={12} /> : <Eye size={12} />}
                                                        </IconButton>
                                                    </Tooltip>
                                                    <Tooltip title="Copy password">
                                                        <IconButton size="small" sx={{ opacity: 0.4, '&:hover': { opacity: 1 } }} onClick={() => copyToClipboard(c.password!, 'Password')}>
                                                            <Copy size={12} />
                                                        </IconButton>
                                                    </Tooltip>
                                                </Box>
                                            ) : <Typography variant="body2" color="text.disabled">{'\u2014'}</Typography>}
                                        </TableCell>
                                        <TableCell>
                                            {hasHash ? (
                                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                                    <Chip label={c.hash!.length > 16 ? c.hash!.substring(0, 16) + '\u2026' : c.hash}
                                                        size="small" variant="outlined"
                                                        sx={{ fontFamily: 'monospace', fontSize: '0.65rem', color: 'warning.main', borderColor: 'warning.dark' }} />
                                                    <Tooltip title="Copy hash">
                                                        <IconButton size="small" sx={{ opacity: 0.4, '&:hover': { opacity: 1 } }} onClick={() => copyToClipboard(c.hash!, 'Hash')}>
                                                            <Copy size={12} />
                                                        </IconButton>
                                                    </Tooltip>
                                                </Box>
                                            ) : <Typography variant="body2" color="text.disabled">{'\u2014'}</Typography>}
                                        </TableCell>
                                        <TableCell>
                                            <Typography variant="body2" color="text.secondary" fontSize="0.8rem">{c.source || '\u2014'}</Typography>
                                        </TableCell>
                                        <TableCell>
                                            <Chip label={formatAgent(c.agent_id)} size="small" variant="outlined"
                                                color={c.agent_id === '00000000-0000-0000-0000-000000000000' ? 'default' : 'primary'}
                                                sx={{ fontFamily: 'monospace', fontSize: '0.65rem' }} />
                                        </TableCell>
                                        <TableCell align="right">
                                            <Tooltip title="Delete credential">
                                                <IconButton size="small" color="error" onClick={() => handleDelete(c.id, c.username)}
                                                    sx={{ opacity: 0.4, '&:hover': { opacity: 1, bgcolor: 'error.main', color: 'white' } }}>
                                                    <Trash2 style={{ width: 16, height: 16 }} />
                                                </IconButton>
                                            </Tooltip>
                                        </TableCell>
                                    </TableRow>
                                    {hasHash && (
                                        <TableRow key={`${c.id}-x`}>
                                            <TableCell colSpan={8} sx={{ py: 0 }}>
                                                <Collapse in={expanded} timeout="auto" unmountOnExit>
                                                    <Box sx={{ py: 1.5, px: 2, bgcolor: 'rgba(0,0,0,0.2)', borderRadius: 1, mb: 1 }}>
                                                        <Typography variant="caption" color="text.secondary" display="block" mb={0.5}>Full Hash</Typography>
                                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                                            <Typography variant="body2" fontFamily="monospace" color="warning.main"
                                                                sx={{ wordBreak: 'break-all', fontSize: '0.78rem' }}>
                                                                {c.hash}
                                                            </Typography>
                                                            <Tooltip title="Copy full hash">
                                                                <IconButton size="small" onClick={() => copyToClipboard(c.hash!, 'Hash')}>
                                                                    <Copy size={14} />
                                                                </IconButton>
                                                            </Tooltip>
                                                        </Box>
                                                    </Box>
                                                </Collapse>
                                            </TableCell>
                                        </TableRow>
                                    )}
                                </>
                            );
                        })}
                    </TableBody>
                </Table>
            </TableContainer>

            {/* Add Credential Dialog */}
            <Dialog open={showModal} onClose={() => setShowModal(false)} maxWidth="sm" fullWidth>
                <DialogTitle sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: 1, borderColor: 'divider', pb: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                        <ShieldAlert style={{ width: 20, height: 20, color: '#b8bb26' }} />
                        <Typography variant="h6" fontWeight="bold">Add Credential</Typography>
                    </Box>
                    <IconButton size="small" onClick={() => setShowModal(false)}><X style={{ width: 18, height: 18 }} /></IconButton>
                </DialogTitle>
                <DialogContent sx={{ pt: 3 }}>
                    <form id="add-cred-form" onSubmit={handleCreate}>
                        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
                            <TextField label="Domain" placeholder="NT AUTHORITY" value={formData.domain} size="small" fullWidth
                                onChange={(e) => setFormData({ ...formData, domain: e.target.value })} />
                            <TextField label="Username *" placeholder="SYSTEM" required value={formData.username} size="small" fullWidth
                                onChange={(e) => setFormData({ ...formData, username: e.target.value })} />
                            <TextField label="Password" placeholder="Plaintext password" value={formData.password} size="small" fullWidth
                                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                                InputProps={{ endAdornment: <InputAdornment position="end"><Key style={{ width: 14, height: 14, opacity: 0.3 }} /></InputAdornment> }} />
                            <TextField label="Hash" placeholder="NTLM / LM / SHA1" value={formData.hash} size="small" fullWidth
                                onChange={(e) => setFormData({ ...formData, hash: e.target.value })} />
                            <TextField label="Source" placeholder="LSASS Dump, Registry, Kerberoast..." value={formData.source} size="small" fullWidth
                                onChange={(e) => setFormData({ ...formData, source: e.target.value })} sx={{ gridColumn: 'span 2' }} />
                        </Box>
                    </form>
                </DialogContent>
                <Divider sx={{ borderColor: 'divider' }} />
                <DialogActions sx={{ p: 2.5 }}>
                    <Button onClick={() => setShowModal(false)} color="inherit">Cancel</Button>
                    <Button type="submit" form="add-cred-form" variant="contained" color="primary"
                        disabled={creating || !formData.username.trim()}
                        startIcon={<Key style={{ width: 14, height: 14 }} />}>
                        {creating ? 'Saving...' : 'Save Credential'}
                    </Button>
                </DialogActions>
            </Dialog>

            {/* Delete Confirm Dialog */}
            <Dialog open={confirmState.open} onClose={() => setConfirmState({ open: false, id: '', username: '' })} maxWidth="xs" fullWidth>
                <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                    <Trash2 style={{ width: 20, height: 20, color: '#fb4934' }} />
                    <Typography fontWeight="bold">Delete Credential</Typography>
                </DialogTitle>
                <DialogContent>
                    <Typography variant="body2" color="text.secondary">
                        Delete credential for <strong style={{ color: '#ebdbb2' }}>{confirmState.username}</strong>? This cannot be undone.
                    </Typography>
                </DialogContent>
                <DialogActions sx={{ p: 2 }}>
                    <Button onClick={() => setConfirmState({ open: false, id: '', username: '' })} color="inherit">Cancel</Button>
                    <Button onClick={confirmDelete} variant="contained" color="error">Delete</Button>
                </DialogActions>
            </Dialog>
        </Box>
    );
}
