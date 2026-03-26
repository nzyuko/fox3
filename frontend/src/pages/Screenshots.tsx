import { useState, useEffect, useCallback } from 'react';
import { useNotify } from '../context/NotifyContext';
import { useWebSocket, wsSend } from '../hooks/useWebSocket';
import {
    Box, Typography, Button, CircularProgress, Paper, Chip, IconButton,
    Dialog, DialogContent, Tooltip, Grid
} from '@mui/material';
import { Camera, RefreshCw, Trash2, X, Maximize2 } from 'lucide-react';

interface Screenshot {
    id: string;
    agent_id: string;
    note: string;
    size: number;
    created: string;
}

// Fetch screenshot image as base64 data URL via WebSocket
function ScreenshotImg({ id, sx, alt }: { id: string; sx?: any; alt?: string }) {
    const [src, setSrc] = useState<string | null>(null);
    const [err, setErr] = useState(false);
    useEffect(() => {
        wsSend('screenshots.image', { id })
            .then((res: any) => {
                setSrc(`data:image/bmp;base64,${res.data}`);
            })
            .catch(() => setErr(true));
    }, [id]);
    if (err) return <Camera size={32} style={{ color: '#504945' }} />;
    if (!src) return <CircularProgress size={20} color="secondary" />;
    return <Box component="img" src={src} alt={alt || 'screenshot'} sx={sx} />;
}

export default function Screenshots() {
    const notify = useNotify();
    const [screenshots, setScreenshots] = useState<Screenshot[]>([]);
    const [loading, setLoading] = useState(true);
    const [selected, setSelected] = useState<string | null>(null);
    const { lastEvent } = useWebSocket();

    const fetchAll = useCallback(async () => {
        setLoading(true);
        try {
            const data = await wsSend('screenshots.list', {});
            setScreenshots(data || []);
        } catch (err) {
            if (import.meta.env.DEV) console.error(err);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { fetchAll(); }, [fetchAll]);

    useEffect(() => {
        if (lastEvent?.event === 'screenshot') fetchAll();
    }, [lastEvent, fetchAll]);

    const handleDelete = async (id: string) => {
        try {
            await wsSend('screenshot.delete', { id });
            notify('Screenshot deleted', 'success');
            setScreenshots(s => s.filter(sc => sc.id !== id));
            if (selected === id) setSelected(null);
        } catch (err: any) {
            notify('Delete failed: ' + (err.message || err), 'error');
        }
    };

    return (
        <Box sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3, borderBottom: 1, borderColor: 'divider', pb: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                    <Box sx={{ p: 1, bgcolor: 'rgba(254,128,25,0.12)', borderRadius: 1.5, border: '1px solid rgba(254,128,25,0.25)', display: 'flex' }}>
                        <Camera size={20} color="#fe8019" />
                    </Box>
                    <Box>
                        <Typography variant="h6" fontWeight={800} letterSpacing={0.5}>Screenshots</Typography>
                        <Typography variant="caption" color="text.secondary">
                            {screenshots.length} capture{screenshots.length !== 1 ? 's' : ''}
                        </Typography>
                    </Box>
                </Box>
                <Button variant="outlined" color="secondary" size="small" onClick={fetchAll}
                    startIcon={loading ? <CircularProgress size={14} color="inherit" /> : <RefreshCw size={14} />}
                    sx={{ textTransform: 'none' }}>
                    Refresh
                </Button>
            </Box>

            {loading && screenshots.length === 0 ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', py: 6 }}>
                    <CircularProgress color="secondary" size={28} />
                </Box>
            ) : screenshots.length === 0 ? (
                <Box sx={{ textAlign: 'center', py: 6 }}>
                    <Camera size={48} style={{ color: '#504945', strokeWidth: 1 }} />
                    <Typography color="text.disabled" mt={1.5}>No screenshots captured</Typography>
                    <Typography color="text.disabled" fontSize="0.75rem">Send a "screenshot" command to an agent to capture</Typography>
                </Box>
            ) : (
                <Grid container spacing={2}>
                    {screenshots.map((sc) => (
                        <Grid size={{ xs: 12, sm: 6, md: 4, lg: 3 }} key={sc.id}>
                            <Paper variant="outlined" sx={{
                                borderRadius: 2, overflow: 'hidden', cursor: 'pointer',
                                '&:hover': { borderColor: 'rgba(254,128,25,0.4)' },
                                transition: 'border-color 0.15s',
                            }}>
                                <Box
                                    sx={{ height: 180, bgcolor: '#1d2021', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative' }}
                                    onClick={() => setSelected(sc.id)}
                                >
                                    <ScreenshotImg id={sc.id} sx={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain' }} />
                                    <Box sx={{ position: 'absolute', top: 6, right: 6, opacity: 0.6, '&:hover': { opacity: 1 } }}>
                                        <Tooltip title="Fullscreen">
                                            <IconButton size="small" sx={{ color: 'text.secondary', bgcolor: 'rgba(0,0,0,0.5)' }}>
                                                <Maximize2 size={14} />
                                            </IconButton>
                                        </Tooltip>
                                    </Box>
                                </Box>
                                <Box sx={{ p: 1.5, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <Box>
                                        <Chip label={sc.agent_id.slice(0, 8)} size="small" variant="outlined"
                                            sx={{ height: 18, fontSize: '0.6rem', fontFamily: 'monospace', mb: 0.5 }} />
                                        <Typography variant="caption" display="block" color="text.disabled" fontSize="0.6rem">
                                            {new Date(sc.created).toLocaleString()}
                                        </Typography>
                                        {sc.size > 0 && (
                                            <Typography variant="caption" display="block" color="text.disabled" fontSize="0.55rem">
                                                {Math.round(sc.size / 1024)} KB
                                            </Typography>
                                        )}
                                    </Box>
                                    <Tooltip title="Delete">
                                        <IconButton size="small" color="error" onClick={(e) => { e.stopPropagation(); handleDelete(sc.id); }}>
                                            <Trash2 size={14} />
                                        </IconButton>
                                    </Tooltip>
                                </Box>
                            </Paper>
                        </Grid>
                    ))}
                </Grid>
            )}

            {/* Fullscreen dialog */}
            <Dialog open={!!selected} onClose={() => setSelected(null)} maxWidth="xl" fullWidth
                PaperProps={{ sx: { bgcolor: '#0a0a0a', border: '1px solid rgba(235,219,178,0.08)' } }}>
                <Box sx={{ display: 'flex', justifyContent: 'flex-end', p: 1 }}>
                    <IconButton size="small" onClick={() => setSelected(null)} sx={{ color: 'text.secondary' }}>
                        <X size={18} />
                    </IconButton>
                </Box>
                <DialogContent sx={{ display: 'flex', justifyContent: 'center', p: 2, pt: 0 }}>
                    {selected && (
                        <ScreenshotImg id={selected} sx={{ maxWidth: '100%', maxHeight: '80vh', objectFit: 'contain' }} />
                    )}
                </DialogContent>
            </Dialog>
        </Box>
    );
}
