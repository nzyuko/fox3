import { useState, useEffect, useRef } from 'react';
import { Folder, File, HardDrive, Download, Upload, RefreshCw, ArrowUp, Command } from 'lucide-react';
import {
    Box, Typography, IconButton, Paper, Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
    InputBase, Button, CircularProgress, Dialog, DialogTitle, DialogContent, DialogActions, TextField
} from '@mui/material';

export interface FileNode { name: string; isDir: boolean; size: string; modified: string; permissions: string; }

interface FileBrowserProps {
    agentId: string;
    onsendCommand: (cmd: string) => void;
    currentJobs: any[];
    cachedFiles: FileNode[];
    cachedPath: string;
    onCacheUpdate: (files: FileNode[], path: string) => void;
}

export function parseLsOutput(raw: string): FileNode[] {
    try {
        const data = JSON.parse(raw);
        if (Array.isArray(data)) {
            const parsed: FileNode[] = data.map((f: any) => {
                const ts = f.modified ? new Date(f.modified * 1000) : null;
                return {
                    name: f.name || '',
                    isDir: f.type === 'd',
                    size: f.type === 'd' ? '—' : (f.size != null ? (+f.size).toLocaleString() + ' B' : '—'),
                    modified: ts ? ts.toLocaleString() : 'Unknown',
                    permissions: f.type === 'd' ? 'dir' : f.type === 'l' ? 'link' : 'file',
                };
            });
            parsed.sort((a, b) => { if (a.isDir !== b.isDir) return a.isDir ? -1 : 1; return a.name.localeCompare(b.name); });
            return parsed;
        }
    } catch { /* not JSON — raw text fallback */ }
    const lines = raw.split('\n').map(l => l.trim()).filter(Boolean);
    const parsed: FileNode[] = [];
    for (const line of lines) {
        const p = line.split(/\s+/);
        if (p.length >= 4) parsed.push({ permissions: p[0], isDir: p[0] === 'd', modified: 'Unknown', size: '—', name: p.slice(3).join(' ') });
    }
    parsed.sort((a, b) => { if (a.isDir !== b.isDir) return a.isDir ? -1 : 1; return a.name.localeCompare(b.name); });
    return parsed;
}

export default function FileBrowser({ agentId: _agentId, onsendCommand, currentJobs, cachedFiles, cachedPath, onCacheUpdate }: FileBrowserProps) {
    const [currentPath, setCurrentPath] = useState(cachedPath || 'C:\\');
    const [files, setFiles] = useState<FileNode[]>(cachedFiles || []);
    const [loading, setLoading] = useState(false);
    const [pendingSince, setPendingSince] = useState<number>(0);
    const [lastParsedId, setLastParsedId] = useState<string | null>(null);
    const [uploadOpen, setUploadOpen] = useState(false);
    const [uploadPath, setUploadPath] = useState('');
    const didInitialFetch = useRef(false);

    // Only fetch on first mount if no cached data
    useEffect(() => {
        if (didInitialFetch.current) return;
        didInitialFetch.current = true;
        if (cachedFiles.length === 0) {
            refreshDirectory();
        }
    }, []);

    // Watch currentJobs for completed ls results
    useEffect(() => {
        if (!pendingSince || !currentJobs) return;
        const lsJobs = currentJobs
            .filter((j: any) => (j.command === 'ls' || j.command.startsWith('ls ')) && j.id !== lastParsedId)
            .sort((a: any, b: any) => new Date(b.created).getTime() - new Date(a.created).getTime());
        const latest = lsJobs[0];
        if (latest && (latest.status === 'Complete' || latest.status === 'Returned') && latest.output) {
            const parsed = parseLsOutput(latest.output);
            setFiles(parsed);
            onCacheUpdate(parsed, currentPath);
            setLoading(false);
            setPendingSince(0);
            setLastParsedId(latest.id);
        }
    }, [currentJobs, pendingSince]);

    const refreshDirectory = () => {
        setLoading(true); setFiles([]);
        setPendingSince(Date.now());
        onsendCommand(`ls ${currentPath}`);
    };

    const sep = currentPath.includes('\\') ? '\\' : '/';

    const handleNavigate = (folder: string) => {
        setCurrentPath(p => p.endsWith(sep) ? `${p}${folder}` : `${p}${sep}${folder}`);
    };

    useEffect(() => {
        if (!didInitialFetch.current) return;
        if (currentPath !== cachedPath) refreshDirectory();
    }, [currentPath]);

    const navigateUp = () => {
        const parts = currentPath.split(sep).filter(Boolean);
        if (parts.length <= 1) { setCurrentPath(currentPath.includes('\\') ? 'C:\\' : '/'); return; }
        parts.pop();
        setCurrentPath(parts.join(sep) + sep);
    };

    const handleDownload = (name: string) => {
        const full = currentPath.endsWith(sep) ? `${currentPath}${name}` : `${currentPath}${sep}${name}`;
        onsendCommand(`download ${full}`);
    };

    const handleUpload = () => {
        if (!uploadPath.trim()) return;
        onsendCommand(`upload ${uploadPath.trim()} ${currentPath}`);
        setUploadOpen(false);
        setUploadPath('');
    };

    return (
        <Box sx={{ flex: 1, bgcolor: '#1d2021', borderRadius: 2, border: '1px solid', borderColor: 'divider', display: 'flex', flexDirection: 'column', overflow: 'hidden', boxShadow: 10 }}>
            {/* Toolbar */}
            <Box sx={{ bgcolor: 'background.paper', borderBottom: '1px solid', borderColor: 'divider', p: 1.5, display: 'flex', alignItems: 'center', gap: 1.5, flexShrink: 0 }}>
                <IconButton onClick={navigateUp} size="small" title="Up" sx={{ color: 'text.secondary', '&:hover': { color: 'text.primary' } }}><ArrowUp size={18} /></IconButton>
                <IconButton onClick={refreshDirectory} disabled={loading} size="small" title="Refresh" sx={{ color: 'text.secondary', '&:hover': { color: 'text.primary' } }}>
                    {loading ? <CircularProgress size={18} color="secondary" /> : <RefreshCw size={18} />}
                </IconButton>
                <Box sx={{ flex: 1, mx: 1, display: 'flex', alignItems: 'center', bgcolor: 'rgba(0,0,0,0.3)', border: '1px solid', borderColor: 'divider', borderRadius: 1, px: 1.5, py: 0.5 }}>
                    <HardDrive size={14} color="#a89984" style={{ marginRight: 8, flexShrink: 0 }} />
                    <InputBase fullWidth value={currentPath} onChange={e => setCurrentPath(e.target.value)}
                        onKeyDown={e => { if (e.key === 'Enter') refreshDirectory(); }}
                        sx={{ color: 'text.primary', fontFamily: 'monospace', fontSize: '0.875rem' }} />
                </Box>
                <Button variant="outlined" color="secondary" size="small" startIcon={<Upload size={14} />}
                    onClick={() => setUploadOpen(true)} sx={{ whiteSpace: 'nowrap' }}>
                    Upload
                </Button>
            </Box>

            {/* File list */}
            <Box sx={{ flex: 1, overflowY: 'auto', p: 2, bgcolor: 'rgba(0,0,0,0.2)' }}>
                {loading && !files.length ? (
                    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'text.secondary' }}>
                        <CircularProgress color="secondary" sx={{ mb: 2 }} />
                        <Typography>Querying remote filesystem...</Typography>
                        <Typography variant="caption" mt={1}>Waiting for agent to return ls results.</Typography>
                    </Box>
                ) : !files.length ? (
                    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'text.secondary' }}>
                        <Folder size={48} style={{ opacity: 0.2, marginBottom: 12 }} />
                        <Typography>Directory is empty or could not be parsed.</Typography>
                    </Box>
                ) : (
                    <TableContainer component={Paper} elevation={0} sx={{ bgcolor: 'transparent', border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
                        <Table size="small" stickyHeader>
                            <TableHead>
                                <TableRow>
                                    {['Type', 'Name', 'Size', 'Date Modified', 'Perms', ''].map(h => (
                                        <TableCell key={h} sx={{ bgcolor: 'background.paper', fontWeight: 'bold', color: 'text.secondary', textTransform: 'uppercase', fontSize: '0.7rem' }}>{h}</TableCell>
                                    ))}
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {files.map((file, idx) => (
                                    <TableRow key={idx} hover sx={{ '&:last-child td': { border: 0 } }}>
                                        <TableCell>{file.isDir ? <Folder size={18} color="#b8bb26" /> : <File size={18} color="#a89984" />}</TableCell>
                                        <TableCell>
                                            {file.isDir ? (
                                                <Typography variant="body2" color="primary.main" fontWeight="medium" onClick={() => handleNavigate(file.name)}
                                                    sx={{ cursor: 'pointer', '&:hover': { textDecoration: 'underline' } }}>
                                                    {file.name}
                                                </Typography>
                                            ) : <Typography variant="body2">{file.name}</Typography>}
                                        </TableCell>
                                        <TableCell><Typography variant="body2" color="text.secondary" fontFamily="monospace" fontSize="0.8rem">{file.size}</Typography></TableCell>
                                        <TableCell><Typography variant="body2" color="text.secondary" fontSize="0.8rem">{file.modified}</Typography></TableCell>
                                        <TableCell><Typography variant="body2" color="text.disabled" fontFamily="monospace" fontSize="0.75rem">{file.permissions}</Typography></TableCell>
                                        <TableCell align="right">
                                            {!file.isDir && (
                                                <IconButton size="small" color="success" onClick={() => handleDownload(file.name)} title="Download"
                                                    sx={{ opacity: 0.3, '&:hover': { opacity: 1, bgcolor: 'success.main', color: 'white' } }}>
                                                    <Download size={14} />
                                                </IconButton>
                                            )}
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    </TableContainer>
                )}
            </Box>

            {/* Footer */}
            <Box sx={{ bgcolor: 'background.paper', borderTop: '1px solid', borderColor: 'divider', px: 2, py: 1, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexShrink: 0 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, color: 'text.secondary', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                    <Command size={12} /><span>Dispatches ls jobs · right-click to download</span>
                </Box>
                <Typography variant="caption" color="text.secondary" fontFamily="monospace">{files.length} items</Typography>
            </Box>

            {/* Upload Dialog */}
            <Dialog open={uploadOpen} onClose={() => setUploadOpen(false)} maxWidth="sm" fullWidth>
                <DialogTitle>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                        <Upload size={18} style={{ color: '#83a598' }} />
                        <Typography fontWeight="bold">Upload File</Typography>
                    </Box>
                </DialogTitle>
                <DialogContent>
                    <Typography variant="body2" color="text.secondary" mb={2}>
                        Enter the full local path of the file to upload. The agent will retrieve it and place it in <code style={{ color: '#83a598' }}>{currentPath}</code>.
                    </Typography>
                    <TextField fullWidth label="Local file path" placeholder="C:\Users\operator\payload.exe"
                        value={uploadPath} onChange={e => setUploadPath(e.target.value)} size="small" autoFocus
                        onKeyDown={e => { if (e.key === 'Enter') handleUpload(); }}
                        InputProps={{ sx: { fontFamily: 'monospace' } }} />
                </DialogContent>
                <DialogActions sx={{ p: 2 }}>
                    <Button onClick={() => setUploadOpen(false)} color="inherit">Cancel</Button>
                    <Button onClick={handleUpload} variant="contained" color="secondary" disabled={!uploadPath.trim()}
                        startIcon={<Upload size={14} />}>Upload</Button>
                </DialogActions>
            </Dialog>
        </Box>
    );
}
