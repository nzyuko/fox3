import { useState, useEffect, useRef } from 'react';
import { Outlet, Link, useLocation } from 'react-router-dom';
import { Activity, Radio, LogOut, Network, Key, Wifi, WifiOff, Camera } from 'lucide-react';
import MissileIcon from '../components/MissileIcon';
import { Box, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Typography, CssBaseline } from '@mui/material';
import { useWebSocket, wsSend, wsDisconnect } from '../hooks/useWebSocket';

const drawerWidth = 200;

interface Stats { agents: number; listeners: number; credentials: number; }

export default function DashboardLayout() {
    const location = useLocation();
    const [stats, setStats] = useState<Stats>({ agents: 0, listeners: 0, credentials: 0 });
    const { lastEvent, connected } = useWebSocket();

    const fetchStats = () => {
        wsSend('stats.get', {})
            .then((s: any) => setStats({ agents: s.agents || 0, listeners: s.listeners || 0, credentials: s.credentials || 0 }))
            .catch(() => {});
    };

    const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);
    useEffect(() => { fetchStats(); }, []);
    useEffect(() => {
        if (!lastEvent) return;
        const triggers = ['agent_checkin', 'agent_removed', 'listener_start', 'listener_stop'];
        if (triggers.includes(lastEvent.event)) {
            if (debounceRef.current) clearTimeout(debounceRef.current);
            debounceRef.current = setTimeout(fetchStats, 500);
        }
    }, [lastEvent]);

    const navItems = [
        { name: 'Agents', path: '/agents', icon: Activity, badge: stats.agents, badgeColor: '#b8bb26' },
        { name: 'Listeners', path: '/listeners', icon: Radio, badge: stats.listeners, badgeColor: '#83a598' },
        { name: 'Topology', path: '/topology', icon: Network, badge: 0, badgeColor: '' },
        { name: 'Screenshots', path: '/screenshots', icon: Camera, badge: 0, badgeColor: '' },
        { name: 'Credentials', path: '/credentials', icon: Key, badge: stats.credentials, badgeColor: '#fabd2f' },
    ];

    const handleLogout = () => {
        wsDisconnect();
        localStorage.removeItem('fox3_token');
        window.location.href = '/login';
    };

    return (
        <Box sx={{ display: 'flex', minHeight: '100vh', bgcolor: 'background.default' }}>
            <CssBaseline />

            {/* Sidebar */}
            <Box sx={{
                width: drawerWidth, flexShrink: 0, height: '100vh', position: 'fixed',
                bgcolor: '#1d2021', borderRight: '1px solid', borderColor: 'rgba(235,219,178,0.06)',
                display: 'flex', flexDirection: 'column', zIndex: 1200,
            }}>
                {/* Logo */}
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, px: 2.5, py: 2, borderBottom: '1px solid', borderColor: 'rgba(235,219,178,0.06)' }}>
                    <Box sx={{ p: 0.75, borderRadius: 1, bgcolor: 'rgba(184,187,38,0.12)', border: '1px solid rgba(184,187,38,0.25)', display: 'flex' }}>
                        <MissileIcon size={18} color="#b8bb26" />
                    </Box>
                    <Typography variant="subtitle2" fontWeight={800} color="#ebdbb2" letterSpacing={3} fontSize="0.9rem">FOX3</Typography>
                    <Box sx={{ ml: 'auto', display: 'flex', alignItems: 'center' }}>
                        {connected ?
                            <Wifi size={12} style={{ color: '#b8bb26', opacity: 0.6 }} /> :
                            <WifiOff size={12} style={{ color: '#fb4934', opacity: 0.6 }} />
                        }
                    </Box>
                </Box>

                {/* Nav */}
                <List sx={{ px: 1, py: 1.5, flex: 1 }}>
                    {navItems.map(({ name, path, icon: Icon, badge, badgeColor }) => {
                        const active = location.pathname.startsWith(path);
                        return (
                            <ListItem key={name} disablePadding sx={{ mb: 0.25 }}>
                                <ListItemButton component={Link} to={path} selected={active} sx={{
                                    borderRadius: 1, py: 0.75, px: 1.5,
                                    '&.Mui-selected': {
                                        bgcolor: 'rgba(184,187,38,0.1)',
                                        borderLeft: '2px solid #b8bb26',
                                        color: '#ebdbb2',
                                        '&:hover': { bgcolor: 'rgba(184,187,38,0.16)' },
                                        '& .MuiListItemIcon-root': { color: '#b8bb26' },
                                    },
                                    '&:not(.Mui-selected)': { borderLeft: '2px solid transparent' },
                                    '&:hover': { bgcolor: 'rgba(235,219,178,0.04)' },
                                }}>
                                    <ListItemIcon sx={{ minWidth: 32, color: active ? '#b8bb26' : '#a89984' }}>
                                        <Icon size={16} />
                                    </ListItemIcon>
                                    <ListItemText primary={name} primaryTypographyProps={{
                                        fontSize: '0.8rem', fontWeight: active ? 700 : 500,
                                        color: active ? '#ebdbb2' : '#a89984', letterSpacing: 0.3,
                                    }} />
                                    {badge > 0 && (
                                        <Typography component="span" sx={{
                                            fontSize: '0.65rem', fontWeight: 700, fontFamily: 'monospace',
                                            color: badgeColor, bgcolor: `${badgeColor}15`,
                                            px: 0.75, py: 0.1, borderRadius: 1, minWidth: 20, textAlign: 'center',
                                        }}>
                                            {badge}
                                        </Typography>
                                    )}
                                </ListItemButton>
                            </ListItem>
                        );
                    })}
                </List>

                {/* Bottom */}
                <Box sx={{ px: 1, pb: 1.5 }}>
                    <Box sx={{ mx: 1, mb: 1, borderTop: '1px solid', borderColor: 'rgba(235,219,178,0.06)' }} />
                    <ListItem disablePadding>
                        <ListItemButton onClick={handleLogout} sx={{
                            borderRadius: 1, py: 0.75, px: 1.5,
                            color: '#a89984',
                            '&:hover': { bgcolor: 'rgba(251,73,52,0.1)', color: '#fb4934', '& .MuiListItemIcon-root': { color: '#fb4934' } },
                        }}>
                            <ListItemIcon sx={{ minWidth: 32, color: 'inherit' }}><LogOut size={16} /></ListItemIcon>
                            <ListItemText primary="Disconnect" primaryTypographyProps={{ fontSize: '0.8rem', fontWeight: 500 }} />
                        </ListItemButton>
                    </ListItem>
                </Box>
            </Box>

            {/* Main content */}
            <Box component="main" sx={{ flexGrow: 1, ml: `${drawerWidth}px`, p: '24px 28px', height: '100vh', overflow: 'auto' }}>
                <Outlet />
            </Box>
        </Box>
    );
}
