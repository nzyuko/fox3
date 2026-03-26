import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { NotifyProvider } from './context/NotifyContext';
import Login from './pages/Login';
import DashboardLayout from './layouts/DashboardLayout';
import Agents from './pages/Agents';
import Listeners from './pages/Listeners';
import Credentials from './pages/Credentials';
import Topology from './pages/Topology';
import Screenshots from './pages/Screenshots';
import AgentDetails from './pages/AgentDetails';

// Fox3 Gruvbox Dark theme
const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#b8bb26',    // gruvbox green
      light: '#d5c4a1',
      dark: '#98971a',
    },
    secondary: {
      main: '#83a598',    // gruvbox aqua
      light: '#8ec07c',
      dark: '#689d6a',
    },
    background: {
      default: '#1d2021', // gruvbox bg0_h
      paper: '#282828',   // gruvbox bg0
    },
    error:   { main: '#fb4934' }, // gruvbox red
    warning: { main: '#fabd2f' }, // gruvbox yellow
    info:    { main: '#83a598' }, // gruvbox aqua
    success: { main: '#b8bb26' }, // gruvbox green
    divider: 'rgba(235,219,178,0.08)', // gruvbox fg faint
    text: {
      primary: '#ebdbb2',   // gruvbox fg
      secondary: '#a89984', // gruvbox gray
      disabled: '#504945',  // gruvbox bg2
    },
  },
  typography: {
    fontFamily: '"JetBrains Mono", "Fira Code", "Consolas", monospace',
  },
  shape: { borderRadius: 4 },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          scrollbarColor: '#3c3836 #1d2021',
          '&::-webkit-scrollbar': { width: 6, height: 6 },
          '&::-webkit-scrollbar-track': { background: '#1d2021' },
          '&::-webkit-scrollbar-thumb': { background: '#3c3836', borderRadius: 3 },
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          borderRadius: 4,
          fontWeight: 600,
          letterSpacing: 0.3,
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          backgroundColor: '#282828',
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: { borderBottomColor: 'rgba(235,219,178,0.06)' },
        head: {
          backgroundColor: '#282828',
          color: '#a89984',
          fontWeight: 700,
          fontSize: '0.7rem',
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
        },
      },
    },
    MuiChip: {
      styleOverrides: { root: { fontWeight: 600 } },
    },
    MuiDialog: {
      styleOverrides: {
        paper: {
          backgroundImage: 'none',
          border: '1px solid rgba(235,219,178,0.08)',
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundImage: 'none',
          backgroundColor: '#1d2021',
          borderRightColor: 'rgba(235,219,178,0.06)',
        },
      },
    },
    MuiTextField: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-root': {
            '& fieldset': { borderColor: 'rgba(235,219,178,0.12)' },
            '&:hover fieldset': { borderColor: 'rgba(235,219,178,0.25)' },
          },
        },
      },
    },
  },
});

function isTokenExpired(token: string): boolean {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return true;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (!payload.exp) return false; // no expiry claim = don't reject
    return payload.exp * 1000 < Date.now();
  } catch {
    return true; // malformed = treat as expired
  }
}

const RequireAuth = ({ children }: { children: any }) => {
  const token = localStorage.getItem('fox3_token');
  if (!token || isTokenExpired(token)) {
    localStorage.removeItem('fox3_token');
    return <Navigate to="/login" replace />;
  }
  return children;
};

function App() {
  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <NotifyProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<Login />} />

            {/* Protected Dashboard Routes */}
            <Route path="/" element={
              <RequireAuth>
                <DashboardLayout />
              </RequireAuth>
            }>
              <Route index element={<Navigate to="/agents" replace />} />
              <Route path="agents" element={<Agents />} />
              <Route path="agents/:id" element={<AgentDetails />} />
              <Route path="listeners" element={<Listeners />} />
              <Route path="credentials" element={<Credentials />} />
              <Route path="topology" element={<Topology />} />
              <Route path="screenshots" element={<Screenshots />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </NotifyProvider>
    </ThemeProvider>
  )
}

export default App;
