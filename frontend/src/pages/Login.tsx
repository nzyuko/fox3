import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import MissileIcon from '../components/MissileIcon';
import axios from 'axios';
import { Box, Button, TextField, Typography, Paper, Alert, CircularProgress } from '@mui/material';
import { wsDisconnect } from '../hooks/useWebSocket';

// Ensure this matches the REST API url configured in api.ts
const API_BASE = 'http://127.0.0.1:8080/api';

export default function Login() {
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    // Clear stale token and close old WS on mount
    useEffect(() => {
        localStorage.removeItem('fox3_token');
        wsDisconnect();
    }, []);

    const handleLogin = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            const res = await axios.post(`${API_BASE}/login`, { password });
            if (res.data && res.data.token) {
                localStorage.setItem('fox3_token', res.data.token);
                navigate('/agents');
            }
        } catch (err: any) {
            setError(err.response?.data || 'Connection failed or unauthorized');
        } finally {
            setLoading(false);
        }
    };

    return (
        <Box
            sx={{
                minHeight: '100vh',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                bgcolor: 'background.default'
            }}
        >
            <Paper
                elevation={12}
                sx={{
                    width: '100%',
                    maxWidth: 400,
                    p: 4,
                    bgcolor: 'background.paper',
                    borderRadius: 3,
                    border: '1px solid',
                    borderColor: 'divider',
                }}
            >
                <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', mb: 4 }}>
                    <Box
                        sx={{
                            p: 2,
                            borderRadius: '50%',
                            bgcolor: 'primary.main',
                            opacity: 0.15,
                            mb: 2,
                            border: '1px solid',
                            borderColor: 'primary.main'
                        }}
                    >
                        <MissileIcon size={40} color="#b8bb26" />
                    </Box>
                    <Typography variant="h4" fontWeight="bold" color="white" letterSpacing={4}>
                        FOX3
                    </Typography>
                    <Typography variant="caption" color="text.secondary" textTransform="uppercase" letterSpacing={2} mt={1}>
                        Command & Control
                    </Typography>
                </Box>

                <form onSubmit={handleLogin}>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                        <TextField
                            type="password"
                            placeholder="Operator Password"
                            variant="outlined"
                            fullWidth
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            disabled={loading}
                            autoFocus
                            inputProps={{
                                style: { textAlign: 'center', letterSpacing: '8px', fontSize: '1.25rem' }
                            }}
                            sx={{
                                '& .MuiOutlinedInput-root': {
                                    bgcolor: 'rgba(0,0,0,0.2)'
                                }
                            }}
                        />

                        {error && (
                            <Alert severity="error" variant="filled" sx={{ borderRadius: 2 }}>
                                {error}
                            </Alert>
                        )}

                        <Button
                            type="submit"
                            variant="contained"
                            color="primary"
                            disabled={loading}
                            fullWidth
                            size="large"
                            sx={{
                                py: 1.5,
                                fontWeight: 'bold',
                                letterSpacing: 1,
                                textTransform: 'uppercase'
                            }}
                        >
                            {loading ? <CircularProgress size={24} color="inherit" /> : 'Enter Console'}
                        </Button>
                    </Box>
                </form>
            </Paper>
        </Box>
    );
}
