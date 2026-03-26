import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import ForceGraph2D from 'react-force-graph-2d';
import { RefreshCw, Network, Server, Radio, Monitor, Crosshair } from 'lucide-react';
import { useWebSocket, wsSend } from '../hooks/useWebSocket';
import { Box, Button, Typography, CircularProgress, Paper, Chip, Tooltip, IconButton } from '@mui/material';

interface GraphEdge { from: string; to: string; }

interface Pivot { id: string; parent_agent_id: string; child_agent_id: string; protocol: string; }

const C = {
    green: '#b8bb26', aqua: '#83a598', red: '#fb4934',
    yellow: '#fabd2f', orange: '#fe8019', gray: '#a89984',
    fg: '#ebdbb2', bg: '#1d2021', bg0: '#282828', bg1: '#3c3836',
};

const getIntegrityColor = (level: number) => {
    if (level >= 16384) return C.red;
    if (level >= 12288) return C.yellow;
    if (level >= 8192)  return C.aqua;
    return C.gray;
};

const getIntegrityLabel = (level: number) => {
    if (level >= 16384) return 'SYS';
    if (level >= 12288) return 'HIGH';
    if (level >= 8192)  return 'MED';
    return 'LOW';
};

const getNodeColor = (node: any) => {
    if (node.group === 'server')   return C.green;
    if (node.group === 'listener') return C.aqua;
    if (node.group === 'agent') {
        if (node.status === 'Dead') return C.gray;
        return getIntegrityColor(node.integrity || 0);
    }
    return C.gray;
};

// ── Canvas shape helpers ──

function hexPath(ctx: CanvasRenderingContext2D, x: number, y: number, r: number) {
    ctx.beginPath();
    for (let i = 0; i < 6; i++) {
        const a = (Math.PI / 3) * i - Math.PI / 6;
        const px = x + r * Math.cos(a), py = y + r * Math.sin(a);
        i === 0 ? ctx.moveTo(px, py) : ctx.lineTo(px, py);
    }
    ctx.closePath();
}

function diamondPath(ctx: CanvasRenderingContext2D, x: number, y: number, r: number) {
    ctx.beginPath();
    ctx.moveTo(x, y - r);
    ctx.lineTo(x + r, y);
    ctx.lineTo(x, y + r);
    ctx.lineTo(x - r, y);
    ctx.closePath();
}

function roundRectPath(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) {
    const l = x - w / 2, t = y - h / 2;
    ctx.beginPath();
    ctx.moveTo(l + r, t);
    ctx.lineTo(l + w - r, t);
    ctx.arcTo(l + w, t, l + w, t + r, r);
    ctx.lineTo(l + w, t + h - r);
    ctx.arcTo(l + w, t + h, l + w - r, t + h, r);
    ctx.lineTo(l + r, t + h);
    ctx.arcTo(l, t + h, l, t + h - r, r);
    ctx.lineTo(l, t + r);
    ctx.arcTo(l, t, l + r, t, r);
    ctx.closePath();
}

// ── Simple crisp icons that work at small sizes ──

function drawServerGlyph(ctx: CanvasRenderingContext2D, x: number, y: number, s: number, color: string) {
    // Three stacked horizontal bars
    ctx.fillStyle = color;
    const bw = s * 0.7, bh = s * 0.16, gap = bh * 1.6;
    for (let i = -1; i <= 1; i++) {
        ctx.fillRect(x - bw / 2, y + i * gap - bh / 2, bw, bh);
    }
}

function drawAntennaGlyph(ctx: CanvasRenderingContext2D, x: number, y: number, s: number, color: string) {
    ctx.strokeStyle = color;
    ctx.lineWidth = Math.max(s * 0.13, 0.8);
    ctx.lineCap = 'round';
    // Mast
    ctx.beginPath();
    ctx.moveTo(x, y - s * 0.3);
    ctx.lineTo(x, y + s * 0.3);
    ctx.stroke();
    // Left/right arms
    ctx.beginPath();
    ctx.moveTo(x - s * 0.25, y - s * 0.15);
    ctx.lineTo(x, y - s * 0.3);
    ctx.lineTo(x + s * 0.25, y - s * 0.15);
    ctx.stroke();
    // Base
    ctx.beginPath();
    ctx.moveTo(x - s * 0.2, y + s * 0.3);
    ctx.lineTo(x + s * 0.2, y + s * 0.3);
    ctx.stroke();
}

function drawTerminalGlyph(ctx: CanvasRenderingContext2D, x: number, y: number, s: number, color: string) {
    // ">" prompt symbol — simple, reads well at any size
    ctx.strokeStyle = color;
    ctx.lineWidth = Math.max(s * 0.16, 0.8);
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    ctx.beginPath();
    ctx.moveTo(x - s * 0.2, y - s * 0.2);
    ctx.lineTo(x + s * 0.1, y);
    ctx.lineTo(x - s * 0.2, y + s * 0.2);
    ctx.stroke();
    // Underscore
    ctx.beginPath();
    ctx.moveTo(x + s * 0.05, y + s * 0.2);
    ctx.lineTo(x + s * 0.25, y + s * 0.2);
    ctx.stroke();
}

// ── Label pill (no roundRect API) ──
function drawLabelPill(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, bgColor: string, borderColor: string) {
    const r = Math.min(h * 0.35, 3);
    roundRectPath(ctx, x, y, w, h, r);
    ctx.fillStyle = bgColor;
    ctx.fill();
    if (borderColor) {
        ctx.strokeStyle = borderColor;
        ctx.lineWidth = 0.4;
        ctx.stroke();
    }
}

const LEGEND = [
    { color: C.green, label: 'Teamserver', shape: 'hex' },
    { color: C.aqua,  label: 'Listener',   shape: 'diamond' },
    { color: C.red,    label: 'SYSTEM',     shape: 'rect' },
    { color: C.yellow, label: 'HIGH',       shape: 'rect' },
    { color: C.aqua,   label: 'MEDIUM',     shape: 'rect' },
    { color: C.gray,   label: 'LOW',        shape: 'rect' },
];

export default function Topology() {
    const navigate = useNavigate();
    const [data, setData] = useState<any>({ nodes: [], links: [] });
    const [loading, setLoading] = useState(true);
    const [hoveredNode, setHoveredNode] = useState<any>(null);
    const hoveredRef = useRef<any>(null); // ref mirror for canvas callback
    const containerRef = useRef<HTMLDivElement>(null);
    const fgRef = useRef<any>(null);
    const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

    const { lastEvent } = useWebSocket();

    const fetchTopology = useCallback(async () => {
        setLoading(true);
        try {
            const [topoData, pivotData] = await Promise.all([
                wsSend('topology.get', {}),
                wsSend('pivots.list', {}).catch(() => [] as Pivot[]),
            ]);
            const topoLinks = (topoData?.edges || []).map((e: GraphEdge) => ({
                source: e.from,
                target: e.to,
                pivot: false,
            }));
            const pivotLinks = (pivotData || []).map((p: Pivot) => ({
                source: p.parent_agent_id,
                target: p.child_agent_id,
                pivot: true,
                protocol: p.protocol,
            }));
            setData({
                nodes: topoData?.nodes || [],
                links: [...topoLinks, ...pivotLinks],
            });
        } catch (err) {
            if (import.meta.env.DEV) console.error(err);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { fetchTopology(); }, [fetchTopology]);

    useEffect(() => {
        if (!lastEvent) return;
        const triggers = ['agent_checkin', 'agent_removed', 'listener_start', 'listener_stop'];
        if (triggers.includes(lastEvent.event)) fetchTopology();
    }, [lastEvent, fetchTopology]);

    useEffect(() => {
        const onResize = () => {
            if (containerRef.current) {
                setDimensions({
                    width: containerRef.current.clientWidth,
                    height: containerRef.current.clientHeight,
                });
            }
        };
        window.addEventListener('resize', onResize);
        onResize();
        return () => window.removeEventListener('resize', onResize);
    }, []);

    const handleNodeClick = useCallback((node: any) => {
        if (node.group === 'agent') navigate(`/agents/${node.id}`);
    }, [navigate]);

    const handleNodeHover = useCallback((node: any) => {
        hoveredRef.current = node || null;
        setHoveredNode(node || null);
        // Cursor management
        const el = containerRef.current;
        if (el) el.style.cursor = node?.group === 'agent' ? 'pointer' : 'default';
    }, []);

    const handleZoomToFit = () => {
        fgRef.current?.zoomToFit(400, 60);
    };

    const counts = data.nodes.reduce((acc: any, n: any) => {
        acc[n.group] = (acc[n.group] || 0) + 1;
        return acc;
    }, {} as Record<string, number>);

    const NODE_R = 11;

    // Canvas renderer — uses hoveredRef (not state) to avoid stale closures
    const paintNode = useCallback((node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
        const color = getNodeColor(node);
        const isDead = node.group === 'agent' && node.status === 'Dead';
        const isHov = hoveredRef.current?.id === node.id;
        const r = NODE_R * (isHov ? 1.15 : 1);

        if (isDead) ctx.globalAlpha = 0.35;

        // ── Outer glow ──
        if (isHov) {
            ctx.save();
            ctx.shadowColor = color;
            ctx.shadowBlur = 12;
        }

        // ── Shape ──
        if (node.group === 'server') {
            hexPath(ctx, node.x, node.y, r);
        } else if (node.group === 'listener') {
            diamondPath(ctx, node.x, node.y, r);
        } else {
            roundRectPath(ctx, node.x, node.y, r * 1.8, r * 1.5, r * 0.22);
        }

        ctx.fillStyle = color + (isHov ? '35' : '18');
        ctx.fill();
        ctx.lineWidth = isHov ? 2 : 1.4;
        ctx.strokeStyle = color + (isHov ? 'ee' : 'aa');
        ctx.stroke();

        if (isHov) ctx.restore();

        // ── Icon glyph ──
        const gs = r * 0.75;
        if (node.group === 'server') {
            drawServerGlyph(ctx, node.x, node.y, gs, color);
        } else if (node.group === 'listener') {
            drawAntennaGlyph(ctx, node.x, node.y, gs, color);
        } else {
            drawTerminalGlyph(ctx, node.x, node.y, gs, color);
        }

        // ── Label ──
        const fontSize = Math.max(10 / globalScale, 2.5);
        ctx.font = `${isHov ? 'bold ' : ''}${fontSize}px monospace`;
        const label = node.label as string;
        const tw = ctx.measureText(label).width;
        const labelY = node.y + r + fontSize * 0.5 + 2;
        const pillW = tw + fontSize * 0.7;
        const pillH = fontSize + fontSize * 0.4;

        drawLabelPill(ctx, node.x, labelY + pillH / 2, pillW, pillH, 'rgba(29,32,33,0.88)', color + '25');

        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillStyle = isHov ? C.fg : C.gray;
        ctx.fillText(label, node.x, labelY);

        // ── Integrity badge (agents only) ──
        if (node.group === 'agent' && node.integrity) {
            const tag = getIntegrityLabel(node.integrity);
            const bf = Math.max(7 / globalScale, 2);
            ctx.font = `bold ${bf}px monospace`;
            const bw = ctx.measureText(tag).width + bf * 0.6;
            const bh = bf * 1.3;
            const bx = node.x + r * 0.6;
            const by = node.y - r * 0.8;

            drawLabelPill(ctx, bx, by, bw, bh, color + '30', color + '55');

            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = color;
            ctx.fillText(tag, bx, by);
        }

        if (isDead) ctx.globalAlpha = 1;
    }, []);

    return (
        <Box sx={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 8rem)' }}>
            {/* Header */}
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, borderBottom: 1, borderColor: 'divider', pb: 2, flexShrink: 0 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                    <Box sx={{ p: 1, bgcolor: 'rgba(131,165,152,0.12)', borderRadius: 1.5, border: '1px solid rgba(131,165,152,0.25)', display: 'flex' }}>
                        <Network size={20} color={C.aqua} />
                    </Box>
                    <Box>
                        <Typography variant="h6" fontWeight={800} color="text.primary" letterSpacing={0.5}>
                            Network Topology
                        </Typography>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mt: 0.25 }}>
                            {counts.server > 0 && (
                                <Chip icon={<Server size={11} />} label={`${counts.server} server`} size="small" variant="outlined"
                                    sx={{ height: 20, fontSize: '0.6rem', fontFamily: 'monospace', color: C.green, borderColor: `${C.green}40` }} />
                            )}
                            {counts.listener > 0 && (
                                <Chip icon={<Radio size={11} />} label={`${counts.listener} listener${counts.listener > 1 ? 's' : ''}`} size="small" variant="outlined"
                                    sx={{ height: 20, fontSize: '0.6rem', fontFamily: 'monospace', color: C.aqua, borderColor: `${C.aqua}40` }} />
                            )}
                            {counts.agent > 0 && (
                                <Chip icon={<Monitor size={11} />} label={`${counts.agent} agent${counts.agent > 1 ? 's' : ''}`} size="small" variant="outlined"
                                    sx={{ height: 20, fontSize: '0.6rem', fontFamily: 'monospace', color: C.fg, borderColor: `${C.fg}25` }} />
                            )}
                            {data.links.length > 0 && (
                                <Typography variant="caption" color="text.disabled" fontFamily="monospace" fontSize="0.6rem">
                                    {data.links.length} edge{data.links.length !== 1 ? 's' : ''}
                                </Typography>
                            )}
                        </Box>
                    </Box>
                </Box>
                <Box sx={{ display: 'flex', gap: 1 }}>
                    <Tooltip title="Zoom to fit">
                        <IconButton size="small" onClick={handleZoomToFit} sx={{ color: 'text.secondary', '&:hover': { color: 'text.primary' } }}>
                            <Crosshair size={16} />
                        </IconButton>
                    </Tooltip>
                    <Button variant="outlined" color="secondary" size="small" onClick={fetchTopology}
                        startIcon={loading ? <CircularProgress size={14} color="inherit" /> : <RefreshCw size={14} />}
                        sx={{ textTransform: 'none' }}>
                        Refresh
                    </Button>
                </Box>
            </Box>

            {/* Graph */}
            <Box ref={containerRef} sx={{ flex: 1, borderRadius: 2, overflow: 'hidden', border: '1px solid', borderColor: 'divider', bgcolor: C.bg, position: 'relative' }}>
                {loading && data.nodes.length === 0 && (
                    <Box sx={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', bgcolor: 'rgba(29,32,33,0.9)', zIndex: 10, gap: 2 }}>
                        <CircularProgress color="secondary" size={32} />
                        <Typography variant="caption" color="text.secondary">Loading topology...</Typography>
                    </Box>
                )}

                {data.nodes.length > 0 && dimensions.width > 0 ? (
                    <ForceGraph2D
                        ref={fgRef}
                        width={dimensions.width}
                        height={dimensions.height}
                        graphData={data}
                        nodeLabel=""
                        nodeRelSize={NODE_R}
                        linkColor={(link: any) => link.pivot ? `${C.orange}80` : `${C.gray}40`}
                        linkWidth={(link: any) => link.pivot ? 1.5 : 1}
                        linkLineDash={(link: any) => link.pivot ? [4, 3] : null}
                        linkDirectionalArrowLength={5}
                        linkDirectionalArrowRelPos={0.9}
                        linkDirectionalParticles={1}
                        linkDirectionalParticleSpeed={0.004}
                        linkDirectionalParticleColor={() => `${C.green}80`}
                        backgroundColor="transparent"
                        d3VelocityDecay={0.3}
                        onNodeClick={handleNodeClick}
                        onNodeHover={handleNodeHover}
                        nodeCanvasObjectMode={() => 'replace'}
                        nodeCanvasObject={paintNode}
                    />
                ) : (
                    !loading && (
                        <Box sx={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 1.5 }}>
                            <Network size={48} style={{ color: C.bg1, strokeWidth: 1 }} />
                            <Typography color="text.disabled" fontSize="0.85rem">No nodes in topology</Typography>
                            <Typography color="text.disabled" fontSize="0.7rem">Start a listener and connect an agent to see the mesh</Typography>
                        </Box>
                    )
                )}

                {/* Legend */}
                <Paper elevation={0} sx={{
                    position: 'absolute', bottom: 12, left: 12,
                    bgcolor: 'rgba(29,32,33,0.92)', backdropFilter: 'blur(6px)',
                    border: '1px solid', borderColor: 'rgba(235,219,178,0.06)',
                    px: 1.5, py: 1, borderRadius: 1.5, minWidth: 130,
                }}>
                    <Typography variant="caption" color="text.disabled" fontWeight={700}
                        sx={{ display: 'block', mb: 0.75, textTransform: 'uppercase', letterSpacing: 1.5, fontSize: '0.55rem' }}>
                        Legend
                    </Typography>
                    {LEGEND.map(({ color, label, shape }) => (
                        <Box key={label} sx={{ display: 'flex', alignItems: 'center', gap: 0.75, mb: 0.35 }}>
                            <Box sx={{
                                width: shape === 'diamond' ? 10 : 12,
                                height: shape === 'diamond' ? 10 : 12,
                                border: `1.5px solid ${color}`,
                                bgcolor: `${color}18`,
                                borderRadius: shape === 'hex' ? '3px' : shape === 'diamond' ? '2px' : '2px',
                                transform: shape === 'diamond' ? 'rotate(45deg) scale(0.85)' : undefined,
                                flexShrink: 0,
                            }} />
                            <Typography variant="caption" color="text.secondary" fontSize="0.63rem" fontFamily="monospace">{label}</Typography>
                        </Box>
                    ))}
                </Paper>

                {/* Hover info panel */}
                {hoveredNode && (
                    <Paper elevation={0} sx={{
                        position: 'absolute', top: 12, right: 12,
                        bgcolor: 'rgba(29,32,33,0.92)', backdropFilter: 'blur(6px)',
                        border: '1px solid', borderColor: 'rgba(235,219,178,0.08)',
                        px: 1.5, py: 1, borderRadius: 1.5, minWidth: 150, maxWidth: 260,
                    }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, mb: 0.5 }}>
                            {hoveredNode.group === 'server' && <Server size={12} color={C.green} />}
                            {hoveredNode.group === 'listener' && <Radio size={12} color={C.aqua} />}
                            {hoveredNode.group === 'agent' && <Monitor size={12} color={getNodeColor(hoveredNode)} />}
                            <Typography variant="caption" fontWeight={700} color="text.primary" fontFamily="monospace" fontSize="0.7rem" noWrap>
                                {hoveredNode.label}
                            </Typography>
                        </Box>
                        <Typography variant="caption" color="text.disabled" fontFamily="monospace" fontSize="0.55rem"
                            sx={{ display: 'block', wordBreak: 'break-all', mb: 0.5 }}>
                            {hoveredNode.id}
                        </Typography>
                        <Box sx={{ display: 'flex', gap: 0.5 }}>
                            <Chip label={hoveredNode.group.toUpperCase()} size="small" variant="outlined"
                                sx={{ height: 16, fontSize: '0.5rem', fontWeight: 700, letterSpacing: 1, fontFamily: 'monospace',
                                    color: getNodeColor(hoveredNode), borderColor: `${getNodeColor(hoveredNode)}50` }} />
                            {hoveredNode.group === 'agent' && hoveredNode.integrity > 0 && (
                                <Chip label={getIntegrityLabel(hoveredNode.integrity)} size="small"
                                    sx={{ height: 16, fontSize: '0.5rem', fontWeight: 700, letterSpacing: 1, fontFamily: 'monospace',
                                        bgcolor: `${getIntegrityColor(hoveredNode.integrity)}20`,
                                        color: getIntegrityColor(hoveredNode.integrity) }} />
                            )}
                        </Box>
                        {hoveredNode.group === 'agent' && (
                            <Typography variant="caption" color="text.disabled" fontSize="0.55rem"
                                sx={{ display: 'block', mt: 0.5, fontStyle: 'italic' }}>
                                Click to interact
                            </Typography>
                        )}
                    </Paper>
                )}
            </Box>
        </Box>
    );
}
