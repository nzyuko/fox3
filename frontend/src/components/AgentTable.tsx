import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Clock, Timer } from 'lucide-react';
import {
    Box, Typography, Chip, Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
    Paper, TableSortLabel
} from '@mui/material';
import type { Agent } from '../pages/Agents';
import { getIntegrityProps, getStatusProps } from '../pages/Agents';

type OrderBy = 'id' | 'host' | 'user' | 'process' | 'platform' | 'integrity' | 'status' | 'sleep' | 'last_checkin';

function LastSeenCell({ lastCheckin }: { lastCheckin: string }) {
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
    return (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, fontFamily: 'monospace', fontSize: '0.7rem', color }}>
            <Clock size={11} />
            <span>{label}</span>
        </Box>
    );
}

function sortComparator(a: Agent, b: Agent, orderBy: OrderBy): number {
    switch (orderBy) {
        case 'integrity': return (a.integrity || 0) - (b.integrity || 0);
        case 'last_checkin': return new Date(a.last_checkin || 0).getTime() - new Date(b.last_checkin || 0).getTime();
        default: {
            const av = String((a as any)[orderBy] || '').toLowerCase();
            const bv = String((b as any)[orderBy] || '').toLowerCase();
            return av.localeCompare(bv);
        }
    }
}

interface AgentTableProps {
    agents: Agent[];
    onContextMenu?: (e: React.MouseEvent, agent: Agent) => void;
}

const columns: { id: OrderBy; label: string; width?: number | string }[] = [
    { id: 'id', label: 'ID', width: 90 },
    { id: 'host', label: 'Host' },
    { id: 'user', label: 'User' },
    { id: 'process', label: 'Process' },
    { id: 'platform', label: 'Platform' },
    { id: 'integrity', label: 'Integrity', width: 100 },
    { id: 'status', label: 'Status', width: 90 },
    { id: 'sleep', label: 'Sleep', width: 80 },
    { id: 'last_checkin', label: 'Last Seen', width: 110 },
];

export default function AgentTable({ agents, onContextMenu }: AgentTableProps) {
    const navigate = useNavigate();
    const [orderBy, setOrderBy] = useState<OrderBy>('last_checkin');
    const [order, setOrder] = useState<'asc' | 'desc'>('desc');

    const handleSort = (col: OrderBy) => {
        if (orderBy === col) setOrder(o => o === 'asc' ? 'desc' : 'asc');
        else { setOrderBy(col); setOrder('asc'); }
    };

    const sorted = [...agents].sort((a, b) => {
        const cmp = sortComparator(a, b, orderBy);
        return order === 'asc' ? cmp : -cmp;
    });

    return (
        <TableContainer component={Paper} variant="outlined" sx={{ bgcolor: 'background.paper', borderRadius: 2 }}>
            <Table size="small" stickyHeader>
                <TableHead>
                    <TableRow>
                        {columns.map(col => (
                            <TableCell key={col.id} sx={{ bgcolor: 'background.paper', fontWeight: 'bold', color: 'text.secondary', textTransform: 'uppercase', fontSize: '0.7rem', width: col.width }}>
                                <TableSortLabel active={orderBy === col.id} direction={orderBy === col.id ? order : 'asc'} onClick={() => handleSort(col.id)}>
                                    {col.label}
                                </TableSortLabel>
                            </TableCell>
                        ))}
                    </TableRow>
                </TableHead>
                <TableBody>
                    {sorted.length === 0 ? (
                        <TableRow>
                            <TableCell colSpan={columns.length} align="center" sx={{ py: 6, color: 'text.secondary', fontStyle: 'italic' }}>
                                No agents match your filter
                            </TableCell>
                        </TableRow>
                    ) : sorted.map(agent => {
                        const priv = getIntegrityProps(agent.integrity || 0);
                        const sp = getStatusProps(agent.status);
                        return (
                            <TableRow key={agent.id} hover
                                onClick={() => navigate(`/agents/${agent.id}`)}
                                onContextMenu={onContextMenu ? (e) => { e.preventDefault(); onContextMenu(e, agent); } : undefined}
                                sx={{
                                    cursor: 'pointer',
                                    '&:last-child td': { border: 0 },
                                    ...(!agent.alive && { opacity: 0.45, filter: 'grayscale(0.6)' }),
                                }}>
                                <TableCell>
                                    <Chip label={agent.id.substring(0, 8)} size="small" color="primary" variant="outlined"
                                        sx={{ fontFamily: 'monospace', fontSize: '0.65rem', height: 20 }} />
                                </TableCell>
                                <TableCell>
                                    <Typography variant="body2" fontWeight="bold">{agent.host}</Typography>
                                </TableCell>
                                <TableCell>
                                    <Typography variant="body2" color="text.secondary">{agent.user}</Typography>
                                </TableCell>
                                <TableCell>
                                    <Typography variant="body2" color="text.secondary" fontFamily="monospace" fontSize="0.78rem">{agent.process}</Typography>
                                </TableCell>
                                <TableCell>
                                    <Typography variant="body2" color="text.secondary" fontSize="0.78rem">{agent.platform}</Typography>
                                </TableCell>
                                <TableCell>
                                    <Chip label={priv.label} size="small" color={priv.color as any}
                                        sx={{ fontSize: '0.6rem', fontWeight: 'bold', letterSpacing: 1, height: 20 }} />
                                </TableCell>
                                <TableCell>
                                    <Chip label={agent.status || 'Init'} size="small" color={sp.color}
                                        variant={agent.status === 'Active' ? 'filled' : 'outlined'}
                                        sx={{ fontWeight: 'bold', fontSize: '0.6rem', height: 20,
                                            ...(agent.status === 'Active' && { color: '#1d2021', opacity: 0.9 }) }} />
                                </TableCell>
                                <TableCell>
                                    {agent.sleep && (
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, color: 'text.secondary', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                                            <Timer size={11} />
                                            <span>{agent.sleep}</span>
                                        </Box>
                                    )}
                                </TableCell>
                                <TableCell>
                                    <LastSeenCell lastCheckin={agent.last_checkin} />
                                </TableCell>
                            </TableRow>
                        );
                    })}
                </TableBody>
            </Table>
        </TableContainer>
    );
}
