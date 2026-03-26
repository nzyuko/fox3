import { useEffect, useRef, useState } from 'react';
import { API_ORIGIN } from '../api';

export interface WSEvent {
    type: 'event';
    event: string;
    payload?: any;
}

interface WSResponse {
    id: string;
    type: 'response';
    success: boolean;
    payload?: any;
    error?: string;
}

type PendingReq = { resolve: (v: any) => void; reject: (e: Error) => void };

let globalWs: WebSocket | null = null;
let globalPending = new Map<string, PendingReq>();
let globalListeners = new Set<(evt: WSEvent) => void>();
let globalReconnectTimer: ReturnType<typeof setTimeout> | null = null;
let globalRetryDelay = 1000;
let globalConnected = false;
let rapidFailCount = 0;
let lastConnectAttempt = 0;
let globalConnectedListeners = new Set<(v: boolean) => void>();
let globalBinaryListeners = new Set<(data: ArrayBuffer) => void>();

function getWsUrl(): string {
    const base = API_ORIGIN.replace(/^http/, 'ws');
    const token = localStorage.getItem('fox3_token');
    return `${base}/api/ws${token ? `?token=${encodeURIComponent(token)}` : ''}`;
}

let reqCounter = 0;
function nextId(): string {
    return `r${++reqCounter}-${Date.now().toString(36)}`;
}

function setConnected(v: boolean) {
    globalConnected = v;
    globalConnectedListeners.forEach(fn => fn(v));
}

function connect() {
    if (globalWs && (globalWs.readyState === WebSocket.CONNECTING || globalWs.readyState === WebSocket.OPEN)) return;

    const url = getWsUrl();
    const ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer'; // Receive binary frames as ArrayBuffer
    globalWs = ws;
    lastConnectAttempt = Date.now();

    ws.onopen = () => {
        globalRetryDelay = 1000;
        rapidFailCount = 0;
        setConnected(true);
    };

    ws.onmessage = (e) => {
        // Binary message — HVNC frame
        if (e.data instanceof ArrayBuffer) {
            if (globalBinaryListeners.size === 0) {
                if (import.meta.env.DEV) console.warn('[ws] binary frame received but no listeners', e.data.byteLength);
            }
            globalBinaryListeners.forEach(fn => fn(e.data));
            return;
        }
        try {
            const msg = JSON.parse(e.data);
            if (msg.type === 'response') {
                const resp = msg as WSResponse;
                const pending = globalPending.get(resp.id);
                if (pending) {
                    globalPending.delete(resp.id);
                    if (resp.success) pending.resolve(resp.payload);
                    else pending.reject(new Error(resp.error || 'unknown error'));
                }
            } else if (msg.type === 'event') {
                const evt = msg as WSEvent;
                globalListeners.forEach(fn => fn(evt));
            }
        } catch { /* ignore malformed */ }
    };

    ws.onclose = (e) => {
        globalWs = null;
        setConnected(false);
        // Reject all pending requests
        globalPending.forEach(p => p.reject(new Error('WebSocket closed')));
        globalPending.clear();

        // 401 = auth failure
        if (e.code === 4001 || e.code === 1008) {
            localStorage.removeItem('fox3_token');
            if (window.location.pathname !== '/login') {
                window.location.href = '/login';
            }
            return;
        }

        // Detect rapid connection failures (stale JWT after server restart)
        // If connection failed within 3s of attempt, count as rapid failure
        if (Date.now() - lastConnectAttempt < 3000) {
            rapidFailCount++;
        } else {
            rapidFailCount = 0;
        }
        if (rapidFailCount >= 3) {
            rapidFailCount = 0;
            localStorage.removeItem('fox3_token');
            if (window.location.pathname !== '/login') {
                window.location.href = '/login';
            }
            return;
        }

        // Reconnect with backoff
        const delay = Math.min(globalRetryDelay, 30000);
        globalRetryDelay = Math.min(delay * 2, 30000);
        globalReconnectTimer = setTimeout(connect, delay);
    };

    ws.onerror = () => {
        // onclose will fire after this
    };
}

function disconnect() {
    if (globalReconnectTimer) {
        clearTimeout(globalReconnectTimer);
        globalReconnectTimer = null;
    }
    if (globalWs) {
        globalWs.close(1000);
        globalWs = null;
    }
    setConnected(false);
}

/**
 * Send a request over the WebSocket and return a promise for the response.
 */
/**
 * Fire-and-forget: send a WS message without waiting for a response.
 * Use for high-frequency events (mouse/keyboard input) where latency matters.
 */
export function wsFire(action: string, payload: any): void {
    if (!globalWs || globalWs.readyState !== WebSocket.OPEN) return;
    globalWs.send(JSON.stringify({ id: nextId(), action, payload }));
}

/**
 * Subscribe to binary WebSocket messages (HVNC frames).
 * Returns an unsubscribe function.
 */
export function onBinaryMessage(fn: (data: ArrayBuffer) => void): () => void {
    globalBinaryListeners.add(fn);
    return () => { globalBinaryListeners.delete(fn); };
}

export function wsSend(action: string, payload: any): Promise<any> {
    // If WS is still connecting, wait for it to open (up to 5s)
    const waitForOpen = (): Promise<void> => {
        if (globalWs && globalWs.readyState === WebSocket.OPEN) return Promise.resolve();
        if (!globalWs || globalWs.readyState === WebSocket.CLOSING || globalWs.readyState === WebSocket.CLOSED) {
            connect(); // ensure connection attempt
        }
        return new Promise((resolve, reject) => {
            const start = Date.now();
            const check = () => {
                if (globalWs && globalWs.readyState === WebSocket.OPEN) { resolve(); return; }
                if (Date.now() - start > 5000) { reject(new Error('WebSocket not connected')); return; }
                setTimeout(check, 100);
            };
            check();
        });
    };

    return waitForOpen().then(() => new Promise((resolve, reject) => {
        const id = nextId();
        globalPending.set(id, { resolve, reject });
        globalWs!.send(JSON.stringify({ id, action, payload }));

        // Timeout after 30s
        setTimeout(() => {
            if (globalPending.has(id)) {
                globalPending.delete(id);
                reject(new Error('request timeout'));
            }
        }, 30000);
    }));
}

/**
 * React hook: subscribe to WebSocket events.
 * Returns the last event and the connected state.
 */
export function useWebSocket(): { lastEvent: WSEvent | null; connected: boolean; send: typeof wsSend } {
    const [lastEvent, setLastEvent] = useState<WSEvent | null>(null);
    const [connected, setConnectedState] = useState(globalConnected);
    const mountedRef = useRef(true);

    useEffect(() => {
        mountedRef.current = true;

        const onEvent = (evt: WSEvent) => {
            if (mountedRef.current) setLastEvent(evt);
        };
        const onConnected = (v: boolean) => {
            if (mountedRef.current) setConnectedState(v);
        };

        globalListeners.add(onEvent);
        globalConnectedListeners.add(onConnected);

        // Start connection if not already running
        connect();

        return () => {
            mountedRef.current = false;
            globalListeners.delete(onEvent);
            globalConnectedListeners.delete(onConnected);
        };
    }, []);

    return { lastEvent, connected, send: wsSend };
}

/**
 * Call once on logout to tear down the global socket.
 */
export function wsDisconnect() {
    disconnect();
}
