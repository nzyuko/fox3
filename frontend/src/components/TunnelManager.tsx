import { useState } from 'react';
import { wsSend } from '../hooks/useWebSocket';
import { useNotify } from '../context/NotifyContext';
import {
    Box, Typography, Button, TextField, Divider, Chip, CircularProgress, Paper, Tooltip
} from '@mui/material';
import { Wifi, WifiOff, Globe, ArrowRightLeft, Play, Square, Info } from 'lucide-react';

interface TunnelManagerProps {
    agentId: string;
}

interface TunnelState {
    active: boolean;
    loading: boolean;
    interface: string;
    port: string;
}

interface RPortFwdState {
    active: boolean;
    loading: boolean;
    listenPort: string;
    forwardHost: string;
    forwardPort: string;
}

export default function TunnelManager({ agentId }: TunnelManagerProps) {
    const notify = useNotify();

    const [socks, setSocks] = useState<TunnelState>({
        active: false, loading: false,
        interface: '127.0.0.1', port: '1080',
    });

    const [rportfwd, setRPortFwd] = useState<RPortFwdState>({
        active: false, loading: false,
        listenPort: '4444', forwardHost: '127.0.0.1', forwardPort: '22',
    });

    const sendJob = async (type: string, args: string[]) => {
        await wsSend('job.create', { agent_id: agentId, type, args });
    };

    const handleSocksToggle = async () => {
        setSocks(s => ({ ...s, loading: true }));
        try {
            if (socks.active) {
                await sendJob('sock_stop', []);
                notify('SOCKS proxy stopped', 'success');
                setSocks(s => ({ ...s, active: false }));
            } else {
                if (!socks.interface.trim() || !socks.port.trim()) {
                    notify('Interface and port are required', 'warning');
                    return;
                }
                await sendJob('sock_start', [socks.interface.trim(), socks.port.trim()]);
                notify(`SOCKS5 proxy started on ${socks.interface}:${socks.port}`, 'success');
                setSocks(s => ({ ...s, active: true }));
            }
        } catch (err: any) {
            notify('Failed: ' + (err.response?.data || err.message), 'error');
        } finally {
            setSocks(s => ({ ...s, loading: false }));
        }
    };

    const handleRPortFwdToggle = async () => {
        setRPortFwd(r => ({ ...r, loading: true }));
        try {
            if (rportfwd.active) {
                await sendJob('rportfwd_stop', []);
                notify('Reverse port forward stopped', 'success');
                setRPortFwd(r => ({ ...r, active: false }));
            } else {
                const { listenPort, forwardHost, forwardPort } = rportfwd;
                if (!listenPort.trim() || !forwardHost.trim() || !forwardPort.trim()) {
                    notify('All reverse port forward fields are required', 'warning');
                    return;
                }
                await sendJob('rportfwd_start', [listenPort.trim(), forwardHost.trim(), forwardPort.trim()]);
                notify(`Reverse port forward: agent :${listenPort} → server → ${forwardHost}:${forwardPort}`, 'success');
                setRPortFwd(r => ({ ...r, active: true }));
            }
        } catch (err: any) {
            notify('Failed: ' + (err.response?.data || err.message), 'error');
        } finally {
            setRPortFwd(r => ({ ...r, loading: false }));
        }
    };

    const StatusBadge = ({ active }: { active: boolean }) => (
        <Chip
            size="small"
            label={active ? 'ACTIVE' : 'INACTIVE'}
            color={active ? 'success' : 'default'}
            variant={active ? 'filled' : 'outlined'}
            sx={{ fontWeight: 'bold', fontSize: '0.65rem', letterSpacing: 1 }}
            icon={active ? <Wifi size={12} /> : <WifiOff size={12} />}
        />
    );

    return (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3, maxWidth: 680 }}>
            {/* Info bar */}
            <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1.5, p: 2, bgcolor: 'rgba(184,187,38,0.08)', borderRadius: 2, border: '1px solid', borderColor: 'rgba(184,187,38,0.2)' }}>
                <Info size={16} style={{ color: '#b8bb26', marginTop: 2, flexShrink: 0 }} />
                <Typography variant="caption" color="text.secondary" lineHeight={1.6}>
                    Tunnel operations are server-side only — the agent does not receive a job. SOCKS runs a local proxy through the agent's network.
                </Typography>
            </Box>

            {/* SOCKS5 Panel */}
            <Paper variant="outlined" sx={{ p: 3, borderRadius: 2, bgcolor: 'background.paper' }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2.5 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                        <Globe size={20} style={{ color: '#83a598' }} />
                        <Box>
                            <Typography fontWeight="bold" color="text.primary">SOCKS5 Proxy</Typography>
                            <Typography variant="caption" color="text.secondary">Routes traffic through the agent's network interface</Typography>
                        </Box>
                    </Box>
                    <StatusBadge active={socks.active} />
                </Box>

                <Box sx={{ display: 'flex', gap: 2, mb: 2.5 }}>
                    <TextField
                        label="Bind Interface"
                        value={socks.interface}
                        onChange={(e) => setSocks(s => ({ ...s, interface: e.target.value }))}
                        disabled={socks.active}
                        size="small"
                        sx={{ flex: 2 }}
                        placeholder="127.0.0.1"
                        InputProps={{ sx: { fontFamily: 'monospace' } }}
                    />
                    <TextField
                        label="Port"
                        value={socks.port}
                        onChange={(e) => setSocks(s => ({ ...s, port: e.target.value }))}
                        disabled={socks.active}
                        size="small"
                        sx={{ flex: 1 }}
                        placeholder="1080"
                        InputProps={{ sx: { fontFamily: 'monospace' } }}
                        inputProps={{ inputMode: 'numeric', pattern: '[0-9]*' }}
                    />
                </Box>

                {socks.active && (
                    <Box sx={{ mb: 2, p: 1.5, bgcolor: 'rgba(184,187,38,0.08)', borderRadius: 1, border: '1px solid', borderColor: 'success.dark' }}>
                        <Typography variant="caption" fontFamily="monospace" color="success.main">
                            SOCKS5 listening on {socks.interface}:{socks.port}
                            <br />
                            Configure tools: proxychains4 / FoxyProxy / curl --socks5 {socks.interface}:{socks.port}
                        </Typography>
                    </Box>
                )}

                <Button
                    variant={socks.active ? 'outlined' : 'contained'}
                    color={socks.active ? 'error' : 'secondary'}
                    onClick={handleSocksToggle}
                    disabled={socks.loading}
                    startIcon={socks.loading ? <CircularProgress size={16} color="inherit" /> : socks.active ? <Square size={16} /> : <Play size={16} />}
                    sx={{ letterSpacing: 0.5 }}
                >
                    {socks.loading ? 'Working...' : socks.active ? 'Stop SOCKS Proxy' : 'Start SOCKS Proxy'}
                </Button>
            </Paper>

            <Divider sx={{ borderColor: 'divider' }} />

            {/* Reverse Port Forward Panel */}
            <Paper variant="outlined" sx={{ p: 3, borderRadius: 2, bgcolor: 'background.paper' }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2.5 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                        <ArrowRightLeft size={20} style={{ color: '#fe8019' }} />
                        <Box>
                            <Typography fontWeight="bold" color="text.primary">Reverse Port Forward</Typography>
                            <Typography variant="caption" color="text.secondary">Agent listens on port → traffic relayed to server → forwarded to target</Typography>
                        </Box>
                    </Box>
                    <StatusBadge active={rportfwd.active} />
                </Box>

                <Box sx={{ display: 'flex', gap: 2, mb: 2.5, alignItems: 'center' }}>
                    <TextField
                        label="Agent Listen Port"
                        value={rportfwd.listenPort}
                        onChange={(e) => setRPortFwd(r => ({ ...r, listenPort: e.target.value }))}
                        disabled={rportfwd.active}
                        size="small"
                        sx={{ flex: 1 }}
                        placeholder="4444"
                        InputProps={{ sx: { fontFamily: 'monospace' } }}
                        inputProps={{ inputMode: 'numeric', pattern: '[0-9]*' }}
                    />
                    <Tooltip title="Traffic flows: Remote Client → Agent:port → C2 → Forward Host:Port">
                        <ArrowRightLeft size={18} style={{ color: '#a89984', flexShrink: 0 }} />
                    </Tooltip>
                    <TextField
                        label="Forward Host"
                        value={rportfwd.forwardHost}
                        onChange={(e) => setRPortFwd(r => ({ ...r, forwardHost: e.target.value }))}
                        disabled={rportfwd.active}
                        size="small"
                        sx={{ flex: 2 }}
                        placeholder="127.0.0.1"
                        InputProps={{ sx: { fontFamily: 'monospace' } }}
                    />
                    <TextField
                        label="Forward Port"
                        value={rportfwd.forwardPort}
                        onChange={(e) => setRPortFwd(r => ({ ...r, forwardPort: e.target.value }))}
                        disabled={rportfwd.active}
                        size="small"
                        sx={{ flex: 1 }}
                        placeholder="22"
                        InputProps={{ sx: { fontFamily: 'monospace' } }}
                        inputProps={{ inputMode: 'numeric', pattern: '[0-9]*' }}
                    />
                </Box>

                {rportfwd.active && (
                    <Box sx={{ mb: 2, p: 1.5, bgcolor: 'rgba(254,128,25,0.08)', borderRadius: 1, border: '1px solid', borderColor: 'rgba(254,128,25,0.3)' }}>
                        <Typography variant="caption" fontFamily="monospace" color="warning.main">
                            Agent listening on :{rportfwd.listenPort} → C2 → {rportfwd.forwardHost}:{rportfwd.forwardPort}
                            <br />
                            Remote clients connecting to agent:{rportfwd.listenPort} are tunneled through C2
                        </Typography>
                    </Box>
                )}

                <Button
                    variant={rportfwd.active ? 'outlined' : 'contained'}
                    color={rportfwd.active ? 'error' : 'warning'}
                    onClick={handleRPortFwdToggle}
                    disabled={rportfwd.loading}
                    startIcon={rportfwd.loading ? <CircularProgress size={16} color="inherit" /> : rportfwd.active ? <Square size={16} /> : <Play size={16} />}
                    sx={{ letterSpacing: 0.5 }}
                >
                    {rportfwd.loading ? 'Working...' : rportfwd.active ? 'Stop Reverse Forward' : 'Start Reverse Forward'}
                </Button>
            </Paper>
        </Box>
    );
}
