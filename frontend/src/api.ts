import axios from 'axios';

const API_BASE = `${import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8080'}/api`;

// Export base URL so other modules can derive WebSocket/SSE URLs
export const API_ORIGIN = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8080';


const api = axios.create({
    baseURL: API_BASE,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Inject JWT token on every request
api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('fox3_token');
        if (token) {
            config.headers['Authorization'] = `Bearer ${token}`;
        }
        return config;
    },
    (error) => Promise.reject(error)
);

// On 401: clear token and redirect to login
api.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            localStorage.removeItem('fox3_token');
            if (window.location.pathname !== '/login') {
                window.location.href = '/login';
            }
        }
        return Promise.reject(error);
    }
);

export default api;
