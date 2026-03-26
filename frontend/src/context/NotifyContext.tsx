import { createContext, useContext, useState, useCallback, type ReactNode } from 'react';
import { Snackbar, Alert, type AlertColor } from '@mui/material';

interface SnackState {
    message: string;
    severity: AlertColor;
    key: number;
}

type NotifyFn = (message: string, severity?: AlertColor) => void;

const NotifyContext = createContext<NotifyFn>(() => {});

export function NotifyProvider({ children }: { children: ReactNode }) {
    const [snack, setSnack] = useState<SnackState | null>(null);
    const [open, setOpen] = useState(false);

    const notify: NotifyFn = useCallback((message, severity = 'info') => {
        setSnack({ message, severity, key: Date.now() });
        setOpen(true);
    }, []);

    return (
        <NotifyContext.Provider value={notify}>
            {children}
            <Snackbar
                key={snack?.key}
                open={open}
                autoHideDuration={4000}
                onClose={() => setOpen(false)}
                anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
            >
                <Alert
                    onClose={() => setOpen(false)}
                    severity={snack?.severity ?? 'info'}
                    variant="filled"
                    sx={{ minWidth: 300, fontWeight: 500 }}
                >
                    {snack?.message}
                </Alert>
            </Snackbar>
        </NotifyContext.Provider>
    );
}

export const useNotify = () => useContext(NotifyContext);
