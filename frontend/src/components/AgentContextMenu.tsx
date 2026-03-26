import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Terminal, Folder, Activity, Monitor, Edit2, Trash2, Power } from 'lucide-react';
import {
    Menu, MenuItem, ListItemIcon, ListItemText, Divider, Box, Typography,
    Dialog, DialogTitle, DialogContent, DialogActions, Button, TextField
} from '@mui/material';
import { wsSend } from '../hooks/useWebSocket';
import { useNotify } from '../context/NotifyContext';
import type { Agent } from '../pages/Agents';

interface AgentContextMenuProps {
    agent: Agent | null;
    anchorPosition: { mouseX: number; mouseY: number } | null;
    onClose: () => void;
    onAgentRemoved?: (id: string) => void;
}

export default function AgentContextMenu({ agent, anchorPosition, onClose, onAgentRemoved }: AgentContextMenuProps) {
    const navigate = useNavigate();
    const notify = useNotify();
    const [noteOpen, setNoteOpen] = useState(false);
    const [noteValue, setNoteValue] = useState('');
    const [deleteOpen, setDeleteOpen] = useState(false);
    const [killOpen, setKillOpen] = useState(false);
    // Capture agent snapshot when dialogs open so it survives onClose nulling the prop
    const agentRef = useRef<Agent | null>(null);
    if (agent) agentRef.current = agent;
    const ag = agentRef.current;

    if (!ag) return null;

    const handleNavigate = (tab?: string) => {
        onClose();
        navigate(`/agents/${ag.id}${tab ? `?tab=${tab}` : ''}`);
    };

    const handleOpenNote = () => {
        setNoteValue(ag.note || '');
        setNoteOpen(true);
        onClose();
    };

    const handleSaveNote = async () => {
        try {
            await wsSend('agent.note', { agent_id: ag.id, note: noteValue });
            notify('Note saved', 'success');
        } catch { notify('Failed to save note', 'error'); }
        setNoteOpen(false);
    };

    const handleOpenKill = () => {
        setKillOpen(true);
        onClose();
    };

    const handleKill = async () => {
        try {
            await wsSend('job.create', { agent_id: ag.id, type: 'exit', args: [] });
            notify('Kill command sent', 'success');
        } catch { notify('Failed to send kill command', 'error'); }
        setKillOpen(false);
    };

    const handleOpenDelete = () => {
        setDeleteOpen(true);
        onClose();
    };

    const handleDelete = async () => {
        try {
            await wsSend('agent.delete', { id: ag.id });
            notify('Agent removed', 'success');
            onAgentRemoved?.(ag.id);
        } catch { notify('Failed to remove agent', 'error'); }
        setDeleteOpen(false);
    };

    return (
        <>
            <Menu
                open={!!anchorPosition}
                onClose={onClose}
                anchorReference="anchorPosition"
                anchorPosition={anchorPosition ? { top: anchorPosition.mouseY, left: anchorPosition.mouseX } : undefined}
                PaperProps={{ sx: { bgcolor: 'background.paper', border: '1px solid', borderColor: 'divider', minWidth: 200, backgroundImage: 'none' } }}
            >
                <Box sx={{ px: 2, py: 1, borderBottom: '1px solid', borderColor: 'divider', mb: 0.5, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Typography variant="caption" color="text.secondary" fontWeight="bold" textTransform="uppercase">Agent</Typography>
                    <Typography variant="caption" color="primary.main" fontFamily="monospace" fontWeight="bold">{ag.host}</Typography>
                </Box>
                <MenuItem onClick={() => handleNavigate()}>
                    <ListItemIcon><Terminal size={16} color="#b8bb26" /></ListItemIcon>
                    <ListItemText primary="Interact" primaryTypographyProps={{ variant: 'body2' }} />
                </MenuItem>
                <MenuItem onClick={() => handleNavigate('files')}>
                    <ListItemIcon><Folder size={16} color="#83a598" /></ListItemIcon>
                    <ListItemText primary="Browse Files" primaryTypographyProps={{ variant: 'body2' }} />
                </MenuItem>
                <MenuItem onClick={() => handleNavigate('processes')}>
                    <ListItemIcon><Activity size={16} color="#fabd2f" /></ListItemIcon>
                    <ListItemText primary="View Processes" primaryTypographyProps={{ variant: 'body2' }} />
                </MenuItem>
                <MenuItem onClick={() => handleNavigate('hvnc')}>
                    <ListItemIcon><Monitor size={16} color="#d3869b" /></ListItemIcon>
                    <ListItemText primary="HVNC" primaryTypographyProps={{ variant: 'body2' }} />
                </MenuItem>
                <MenuItem onClick={handleOpenNote}>
                    <ListItemIcon><Edit2 size={16} color="#a89984" /></ListItemIcon>
                    <ListItemText primary="Set Note" primaryTypographyProps={{ variant: 'body2' }} />
                </MenuItem>
                <Divider sx={{ my: 0.5, borderColor: 'divider' }} />
                <MenuItem onClick={handleOpenKill} sx={{ color: 'warning.main', '&:hover': { bgcolor: 'warning.main', color: 'black' } }}>
                    <ListItemIcon><Power size={16} color="inherit" /></ListItemIcon>
                    <ListItemText primary="Kill Agent" primaryTypographyProps={{ variant: 'body2' }} />
                </MenuItem>
                <MenuItem onClick={handleOpenDelete} sx={{ color: 'error.main', '&:hover': { bgcolor: 'error.main', color: 'white' } }}>
                    <ListItemIcon><Trash2 size={16} color="inherit" /></ListItemIcon>
                    <ListItemText primary="Remove Agent" primaryTypographyProps={{ variant: 'body2' }} />
                </MenuItem>
            </Menu>

            {/* Note Dialog */}
            <Dialog open={noteOpen} onClose={() => setNoteOpen(false)} maxWidth="xs" fullWidth>
                <DialogTitle><Typography fontWeight="bold">Set Note — {ag.host}</Typography></DialogTitle>
                <DialogContent>
                    <TextField fullWidth size="small" placeholder="Operator note..." value={noteValue}
                        onChange={e => setNoteValue(e.target.value)} autoFocus sx={{ mt: 1 }}
                        onKeyDown={e => { if (e.key === 'Enter') handleSaveNote(); }}
                        InputProps={{ sx: { fontFamily: 'monospace' } }} />
                </DialogContent>
                <DialogActions sx={{ p: 2 }}>
                    <Button onClick={() => setNoteOpen(false)} color="inherit">Cancel</Button>
                    <Button onClick={handleSaveNote} variant="contained" color="primary">Save</Button>
                </DialogActions>
            </Dialog>

            {/* Kill Confirm Dialog */}
            <Dialog open={killOpen} onClose={() => setKillOpen(false)} maxWidth="xs" fullWidth>
                <DialogTitle>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                        <Power size={20} style={{ color: '#fabd2f' }} />
                        <Typography fontWeight="bold">Kill Agent</Typography>
                    </Box>
                </DialogTitle>
                <DialogContent>
                    <Typography variant="body2" color="text.secondary">
                        Send exit command to <strong style={{ color: '#ebdbb2' }}>{ag.host}</strong> ({ag.id.substring(0, 8)})? The agent process will terminate on next check-in.
                    </Typography>
                </DialogContent>
                <DialogActions sx={{ p: 2 }}>
                    <Button onClick={() => setKillOpen(false)} color="inherit">Cancel</Button>
                    <Button onClick={handleKill} variant="contained" color="warning">Kill</Button>
                </DialogActions>
            </Dialog>

            {/* Delete Confirm Dialog */}
            <Dialog open={deleteOpen} onClose={() => setDeleteOpen(false)} maxWidth="xs" fullWidth>
                <DialogTitle>
                    <Typography fontWeight="bold">Remove Agent</Typography>
                </DialogTitle>
                <DialogContent>
                    <Typography variant="body2" color="text.secondary">
                        Remove <strong style={{ color: '#ebdbb2' }}>{ag.host}</strong> ({ag.id.substring(0, 8)})? This cannot be undone.
                    </Typography>
                </DialogContent>
                <DialogActions sx={{ p: 2 }}>
                    <Button onClick={() => setDeleteOpen(false)} color="inherit">Cancel</Button>
                    <Button onClick={handleDelete} variant="contained" color="error">Remove</Button>
                </DialogActions>
            </Dialog>
        </>
    );
}
