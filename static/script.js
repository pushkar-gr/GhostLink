// --- State Management ---
const state = {
    fullAddress: null,
    peerAddress: null,
    natType: 'Unknown',
    connectionStatus: 'disconnected', // disconnected, punching, connected
    isIpValid: false,
    isPortValid: false,
    sseSource: null,
    lastSavedMessage: null, // For storing the message on timeout
};

// --- DOM Elements ---
const els = {
    // Views
    viewHome: document.getElementById('view-home'),
    viewPunching: document.getElementById('view-punching'),
    viewConnected: document.getElementById('view-connected'),

    // Shared
    statusText: document.getElementById('statusText'),
    statusBadge: document.getElementById('statusBadge'),
    statusDot: document.querySelector('#statusBadge .status-dot'),

    // Home
    myIpDisplay: document.getElementById('myIpDisplay'),
    natTypeDisplay: document.getElementById('natTypeDisplay'), // New NAT Element
    apiErrorMsg: document.getElementById('apiErrorMsg'),
    copyBtn: document.getElementById('copyBtn'),
    refreshBtn: document.getElementById('refreshBtn'),
    connectForm: document.getElementById('connectForm'),
    peerIpInput: document.getElementById('peerIp'),
    peerPortInput: document.getElementById('peerPort'),
    ipError: document.getElementById('ipError'),
    portError: document.getElementById('portError'),
    submitBtn: document.querySelector('#connectForm button'),

    // Punching / Visualization
    vizClientIp: document.getElementById('vizClientIp'),
    vizPeerIp: document.getElementById('vizPeerIp'),
    punchLogs: document.getElementById('punchLogs'),
    punchTimeout: document.getElementById('punchTimeout'),

    // Connected
    connLocalIp: document.getElementById('connLocalIp'),
    connRemoteIp: document.getElementById('connRemoteIp'),
    disconnectBtn: document.getElementById('disconnectBtn'),

    // Toast
    toast: document.getElementById('toast'),
    toastMsg: document.querySelector('#toast .toast-msg'),
};

// --- Initialization ---
async function init() {
    toggleSubmitButton();
    
    // Initial fetch of the complete application state
    await fetchState();
    
    // Connect to SSE for real-time updates
    connectSSE();

    setupEventListeners();
}

// --- State Logic ---

/**
 * Fetches the complete state from the backend via the new /api/state endpoint.
 * Replaces old /api/ip, /api/status, and /api/peer calls.
 */
async function fetchState() {
    if (els.refreshBtn) {
        els.refreshBtn.classList.add('spin');
        els.refreshBtn.disabled = true;
    }
    els.myIpDisplay.style.opacity = '0.5';

    try {
        const res = await fetch('/api/state');
        if (!res.ok) throw new Error(`Server error`);
        
        const jsonResponse = await res.json();
        
        // The server returns: { "state": { public_ip: "...", ... } }
        // We must unwrap the "state" key.
        const appState = jsonResponse.state;
        
        if (appState) {
            syncState(appState);
            renderMyInfo(true);
        } else {
            console.warn("Invalid state structure received", jsonResponse);
            renderMyInfo(false);
        }

    } catch (err) {
        console.warn("State fetch failed", err);
        renderMyInfo(false);
    } finally {
        setTimeout(() => {
            if (els.refreshBtn) {
                els.refreshBtn.classList.remove('spin');
                els.refreshBtn.disabled = false;
            }
            els.myIpDisplay.style.opacity = '1';
        }, 500);
    }
}

/**
 * Centralizes logic for updating the frontend state from a backend AppState object.
 * Can be called from the REST API fetch or from an SSE Disconnected event.
 */
function syncState(data) {
    if (!data) return;

    // 1. Public IP
    if (data.public_ip) state.fullAddress = data.public_ip;
    
    // 2. Peer IP
    if (data.peer_ip) state.peerAddress = data.peer_ip;
    else if (data.peer_ip === null) state.peerAddress = null; // Explicit reset

    // 3. NAT Type (New)
    if (data.nat_type) {
        state.natType = data.nat_type;
        renderNatType();
    }

    // 4. Status
    if (data.status) {
        // reuse handleStatusChange to trigger UI transitions if needed,
        // but strictly speaking, fetchState is usually for init/refresh.
        // We pass the whole data object so handleStatusChange can see the fields.
        handleStatusChange(data.status, data);
    }
}

function handleStatusChange(statusStr, data = {}) {
    const normStatus = (statusStr || 'DISCONNECTED').toUpperCase();
    
    // Handle Data Syncing based on Event Structure vs API Structure
    
    // CASE A: Disconnected Event via SSE (AppEvent::Disconnected { state })
    if (normStatus === 'DISCONNECTED' && data.state) {
        syncState(data.state);
    }
    // CASE B: Standard AppState via REST API (/api/state) or top-level event fields
    // (Note: syncState calls handleStatusChange, so we avoid infinite recursion by not calling syncState back)
    
    // Logic: Transitioning FROM Punching TO Disconnected
    if (state.connectionStatus === 'punching' && normStatus === 'DISCONNECTED') {
        if (state.lastSavedMessage) {
            showToast(state.lastSavedMessage);
            state.lastSavedMessage = null;
        }
    }

    state.connectionStatus = normStatus.toLowerCase();
    
    // 1. Update Badge
    renderStatusBadge();

    // 2. Switch Views
    els.viewHome.classList.remove('active');
    els.viewPunching.classList.remove('active');
    els.viewConnected.classList.remove('active');

    if (normStatus === 'PUNCHING') {
        enterPunchingState(data);
    } else if (normStatus === 'CONNECTED') {
        enterConnectedState(data);
    } else {
        // DISCONNECTED
        els.viewHome.classList.add('active');
    }
}

async function enterPunchingState(data) {
    els.viewPunching.classList.add('active');
    
    // If peer info is missing locally, we rely on fetchState or what we have.
    // Since /api/peer is gone, we don't fetch it explicitly anymore.
    // It should have been synced via fetchState() or previous input.
    
    els.vizClientIp.innerText = state.fullAddress || "Unknown";
    els.vizPeerIp.innerText = state.peerAddress || "Target";

    // Handle Timeout Display (from AppEvent::Punching { timeout })
    if (data.timeout !== undefined && data.timeout !== null) {
        els.punchTimeout.innerText = `${data.timeout}s`;
        
        if (data.timeout === 0 && data.message) {
            state.lastSavedMessage = data.message;
        }
    }

    // Handle Logs (from AppEvent::Punching { message })
    if (data.message) {
        addLog(data.message);
    }
}

async function enterConnectedState(data) {
    els.viewConnected.classList.add('active');

    els.connLocalIp.innerText = state.fullAddress;
    els.connRemoteIp.innerText = state.peerAddress || "Connected Peer";

    if (data.message) {
        console.log("Connected:", data.message);
    }
}

// --- SSE (Real-time Events) ---
function connectSSE() {
    if (state.sseSource && state.sseSource.readyState !== EventSource.CLOSED) {
        return; 
    }

    // Endpoint: /api/events
    state.sseSource = new EventSource('/api/events');

    state.sseSource.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            
            // AppEvent Structure: 
            // { status: "DISCONNECTED", state: { ... } }
            // { status: "PUNCHING", timeout: 10, message: "..." }
            // { status: "CONNECTED", message: "..." }

            if (data.status) {
                handleStatusChange(data.status, data);
            }
        } catch (e) {
            console.error("SSE Parse Error", e);
        }
    };

    state.sseSource.onerror = (err) => {
        console.warn("SSE Connection issue", err);
    };
}

// --- UI Rendering ---

function renderNatType() {
    if (!els.natTypeDisplay) return;
    
    const type = state.natType;
    els.natTypeDisplay.innerText = type;
    
    // Remove old classes
    els.natTypeDisplay.classList.remove('cone', 'symmetric');
    
    // Add specific color class
    if (type.toLowerCase().includes('cone')) {
        els.natTypeDisplay.classList.add('cone');
    } else if (type.toLowerCase().includes('symmetric')) {
        els.natTypeDisplay.classList.add('symmetric');
    }
}

function renderStatusBadge() {
    const s = state.connectionStatus;
    els.statusText.innerText = s.charAt(0).toUpperCase() + s.slice(1);
    
    let color, bg, border;
    if (s === 'connected') {
        color = 'var(--success)'; bg = 'rgba(16, 185, 129, 0.1)'; border = 'rgba(16, 185, 129, 0.2)';
    } else if (s === 'punching') {
        color = '#f59e0b'; bg = 'rgba(245, 158, 11, 0.1)'; border = 'rgba(245, 158, 11, 0.2)';
    } else {
        color = 'var(--danger)'; bg = 'rgba(239, 68, 68, 0.1)'; border = 'rgba(239, 68, 68, 0.2)';
    }

    els.statusDot.style.backgroundColor = color;
    els.statusDot.style.boxShadow = `0 0 8px ${color}`;
    els.statusBadge.style.color = color;
    els.statusBadge.style.background = bg;
    els.statusBadge.style.borderColor = border;
}

function renderMyInfo(success) {
    if (success && state.fullAddress) {
        els.myIpDisplay.innerText = state.fullAddress;
        els.myIpDisplay.classList.remove('error');
        els.apiErrorMsg.style.display = 'none';
        els.copyBtn.style.display = 'flex';
    } else {
        els.myIpDisplay.innerText = "Connection Failed";
        els.myIpDisplay.classList.add('error');
        els.apiErrorMsg.innerText = "Could not reach node.";
        els.apiErrorMsg.style.display = 'block';
        els.copyBtn.style.display = 'none';
    }
}

function addLog(message) {
    const row = document.createElement('div');
    row.className = `log-line system`; 
    const timeStr = new Date().toLocaleTimeString('en-US', {hour12: false, hour:"2-digit", minute:"2-digit", second:"2-digit"});
    row.innerHTML = `<span class="log-timestamp">[${timeStr}]</span> ${message}`;
    els.punchLogs.appendChild(row);
    els.punchLogs.scrollTop = els.punchLogs.scrollHeight;
}

// --- Interactions ---

async function handleConnect(e) {
    e.preventDefault();
    if (!state.isIpValid || !state.isPortValid) return;

    const ip = els.peerIpInput.value.trim();
    const port = parseInt(els.peerPortInput.value.trim(), 10);
    state.peerAddress = `${ip}:${port}`;

    const btn = els.submitBtn;
    btn.innerText = "Initiating...";
    btn.disabled = true;

    try {
        const res = await fetch('/api/connect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, port })
        });
        if (!res.ok) throw new Error();
        
        els.punchLogs.innerHTML = '';
        state.lastSavedMessage = null;

    } catch (err) {
        showToast("Connection failed to start");
    } finally {
        btn.innerText = "Establish Link";
        btn.disabled = false;
    }
}

async function handleDisconnect() {
    try {
        await fetch('/api/disconnect', { method: 'POST' });
        // UI updates via SSE Disconnected event
    } catch(e) {
        console.error(e);
    }
}

// --- Validation & Utilities ---
function toggleSubmitButton() {
    els.submitBtn.disabled = !(state.isIpValid && state.isPortValid);
}

function showToast(message) {
    els.toastMsg.textContent = message;
    els.toast.classList.add('show');
    setTimeout(() => els.toast.classList.remove('show'), 3000);
}

function copyToClipboard() {
    if (state.fullAddress) {
        const textarea = document.createElement('textarea');
        textarea.value = state.fullAddress;
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            showToast("Copied to clipboard");
        } catch (err) {
            console.error('Copy failed', err);
        }
        document.body.removeChild(textarea);
    }
}

const validators = {
    ip: (ip) => /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip),
    port: (p) => { const n = parseInt(p, 10); return !isNaN(n) && n > 0 && n <= 65535; }
};

function handleIpValidation(eventType) {
    const val = els.peerIpInput.value.trim();
    const isValid = validators.ip(val);
    state.isIpValid = isValid;
    if (isValid) {
        els.peerIpInput.classList.remove('error', 'valid');
        els.peerIpInput.classList.add('valid');
        els.ipError.style.display = 'none';
    } else {
        els.peerIpInput.classList.remove('valid');
        if (eventType === 'blur' && val.length > 0) {
            els.peerIpInput.classList.add('error');
            els.ipError.style.display = 'block';
        } else {
            els.peerIpInput.classList.remove('error');
            els.ipError.style.display = 'none';
        }
    }
    toggleSubmitButton();
}

function handlePortValidation() {
    const val = els.peerPortInput.value.trim();
    const isValid = validators.port(val);
    state.isPortValid = isValid;
    if (isValid) {
        els.peerPortInput.classList.remove('error', 'valid');
        els.peerPortInput.classList.add('valid');
        els.portError.style.display = 'none';
    } else {
        els.peerPortInput.classList.remove('valid');
        if (val.length > 0) {
            els.peerPortInput.classList.add('error');
            els.portError.style.display = 'block';
        } else {
            els.peerPortInput.classList.remove('error');
            els.portError.style.display = 'none';
        }
    }
    toggleSubmitButton();
}

function setupEventListeners() {
    if(els.copyBtn) els.copyBtn.addEventListener('click', copyToClipboard);
    // Updated listener: "Refresh" now calls the unified fetchState
    if(els.refreshBtn) els.refreshBtn.addEventListener('click', fetchState);
    els.connectForm.addEventListener('submit', handleConnect);
    els.disconnectBtn.addEventListener('click', handleDisconnect);
    els.peerIpInput.addEventListener('input', () => handleIpValidation('input'));
    els.peerIpInput.addEventListener('blur', () => handleIpValidation('blur'));
    els.peerPortInput.addEventListener('input', handlePortValidation);
}

init();
