// --- State Management ---
const state = {
    fullAddress: null,
    localAddress: null,
    peerAddress: null,
    natType: 'Unknown',
    connectionStatus: 'disconnected', // disconnected, punching, connected
    isIpValid: false,
    isPortValid: false,
    sseSource: null,
    // NEW: Session state
    fingerprint: null,
    username: null
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
    myLocalIpDisplay: document.getElementById('myLocalIpDisplay'),
    natTypeDisplay: document.getElementById('natTypeDisplay'),
    apiErrorMsg: document.getElementById('apiErrorMsg'),
    copyBtn: document.getElementById('copyBtn'),
    copyLocalBtn: document.getElementById('copyLocalBtn'),
    connectForm: document.getElementById('connectForm'),
    peerIpInput: document.getElementById('peerIp'),
    peerPortInput: document.getElementById('peerPort'),
    usernameInput: document.getElementById('usernameInput'), // New Input
    ipError: document.getElementById('ipError'),
    portError: document.getElementById('portError'),
    submitBtn: document.querySelector('#connectForm button'),

    // Punching / Visualization
    vizClientIp: document.getElementById('vizClientIp'),
    vizPeerIp: document.getElementById('vizPeerIp'),
    punchLogs: document.getElementById('punchLogs'),
    punchTimeout: document.getElementById('punchTimeout'),
    cancelPunchBtn: document.getElementById('cancelPunchBtn'),

    // Connected / Chat
    chatMessages: document.getElementById('chatMessages'),
    chatPeerIp: document.getElementById('chatPeerIp'),
    chatForm: document.getElementById('chatForm'),
    chatInput: document.getElementById('chatInput'),
    sendBtn: document.getElementById('sendBtn'),
    disconnectBtn: document.getElementById('disconnectBtn'),
    verifyIdentityBtn: document.getElementById('verifyIdentityBtn'), // New Button

    // SAS Modal (New)
    sasModal: document.getElementById('sasModal'),
    sasDisplay: document.getElementById('sasDisplay'),
    closeSasBtn: document.getElementById('closeSasBtn'),

    // Toast
    toast: document.getElementById('toast'),
    toastMsg: document.querySelector('#toast .toast-msg'),
};

// --- Initialization ---
async function init() {
    toggleSubmitButton();
    await fetchState();
    connectSSE();
    setupEventListeners();
}

// --- State Logic ---

async function fetchState() {
    els.myIpDisplay.style.opacity = '0.5';

    try {
        const res = await fetch('/api/state');
        if (!res.ok) throw new Error(`Server error`);
        
        const jsonResponse = await res.json();
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
            els.myIpDisplay.style.opacity = '1';
        }, 500);
    }
}

function syncState(data) {
    if (!data) return;

    if (data.public_ip) state.fullAddress = data.public_ip;
    if (data.local_ip) state.localAddress = data.local_ip;
    
    if (data.peer_ip) state.peerAddress = data.peer_ip;
    else if (data.peer_ip === null) state.peerAddress = null;

    if (data.nat_type) {
        state.natType = data.nat_type;
        renderNatType();
    }

    // Capture Security Fingerprint if available
    if (data.fingerprint) {
        state.fingerprint = data.fingerprint;
    }

    if (data.status) {
        handleStatusChange(data.status, data);
    }
}

function handleStatusChange(statusStr, data = {}) {
    const normStatus = (statusStr || 'DISCONNECTED').toUpperCase();
    
    // Safety check: Close modals if state changes (e.g. disconnects)
    if (els.sasModal) els.sasModal.classList.remove('active');

    if (normStatus === 'DISCONNECTED' && data.state) {
        syncState(data.state);
        renderMyInfo(true);
    }
    
    if (normStatus === 'DISCONNECTED') {
        if (data.message) {
            showToast(data.message);
        }
    }

    // Capture fingerprint from connected event if present
    if (normStatus === 'CONNECTED' && data.fingerprint) {
        state.fingerprint = data.fingerprint;
    }

    state.connectionStatus = normStatus.toLowerCase();
    
    renderStatusBadge();

    els.viewHome.classList.remove('active');
    els.viewPunching.classList.remove('active');
    els.viewConnected.classList.remove('active');

    resetDisconnectButtons();

    if (normStatus === 'PUNCHING') {
        enterPunchingState(data);
    } else if (normStatus === 'CONNECTED') {
        enterConnectedState(data);
    } else {
        els.viewHome.classList.add('active');
        els.submitBtn.disabled = !(state.isIpValid && state.isPortValid);
        els.submitBtn.innerText = "INITIATE LINK SEQUENCE";
        // Reset per-session state
        state.fingerprint = null;
    }
}

function resetDisconnectButtons() {
    if(els.disconnectBtn) els.disconnectBtn.disabled = false;
    if(els.cancelPunchBtn) {
        els.cancelPunchBtn.disabled = false;
        els.cancelPunchBtn.innerText = "ABORT SEQUENCE";
    }
}

async function enterPunchingState(data) {
    els.viewPunching.classList.add('active');
    els.vizClientIp.innerText = state.fullAddress || "Unknown";
    els.vizPeerIp.innerText = state.peerAddress || "Target";

    if (data.timeout !== undefined && data.timeout !== null) {
        els.punchTimeout.innerText = `${data.timeout}s`;
    }

    if (data.message) {
        addLog(data.message);
    }
}

async function enterConnectedState(data) {
    els.viewConnected.classList.add('active');
    els.chatPeerIp.innerText = state.peerAddress || "Connected Peer";

    // Update Modal Text
    if (state.fingerprint) {
        els.sasDisplay.innerText = state.fingerprint;
    } else {
        els.sasDisplay.innerText = "VERIFYING...";
    }

    // Optional: Send identity if username was set
    // This logic handles potential double-calls of enterConnectedState
    if (state.username) {
        sendIdentityMessage();
    }
}

function sendIdentityMessage() {
    // Capture and clear immediately to prevent double-send race conditions
    const nameToSend = state.username;
    if (!nameToSend) return;
    state.username = null;

    // Small delay to ensure connection is ready
    setTimeout(async () => {
        try {
            await fetch('/api/message', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: `IDENTIFIED AS: ${nameToSend}` })
            });
        } catch (e) {
            console.warn("Failed to send identity", e);
        }
    }, 500);
}

// --- SSE (Real-time Events) ---
function connectSSE() {
    if (state.sseSource && state.sseSource.readyState !== EventSource.CLOSED) {
        return; 
    }

    state.sseSource = new EventSource('/api/events');

    state.sseSource.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            
            if (data.status) {
                if (data.status === 'MESSAGE') {
                    addChatMessage(data.content, data.from_me);
                } else if (data.status === 'CLEAR_CHAT') {
                    clearChatUI();
                } else {
                    handleStatusChange(data.status, data);
                }
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
    els.natTypeDisplay.classList.remove('cone', 'symmetric');
    if (type.toLowerCase().includes('cone')) {
        els.natTypeDisplay.classList.add('cone');
    } else if (type.toLowerCase().includes('symmetric')) {
        els.natTypeDisplay.classList.add('symmetric');
    }
}

function renderStatusBadge() {
    const s = state.connectionStatus;
    els.statusText.innerText = s.toUpperCase();
    
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
        els.myIpDisplay.innerText = "CONN_FAIL";
        els.myIpDisplay.classList.add('error');
        els.apiErrorMsg.innerText = "COULD NOT REACH NODE";
        els.apiErrorMsg.style.display = 'block';
        els.copyBtn.style.display = 'none';
    }

    if (success && state.localAddress) {
        els.myLocalIpDisplay.innerText = state.localAddress;
        els.myLocalIpDisplay.classList.remove('error');
        els.copyLocalBtn.style.display = 'flex';
    } else {
        els.myLocalIpDisplay.innerText = "N/A";
        els.myLocalIpDisplay.classList.add('error');
        els.copyLocalBtn.style.display = 'none';
    }
}

function addLog(message) {
    const row = document.createElement('div');
    row.className = `log-line system`; 
    const timeStr = new Date().toLocaleTimeString('en-US', {hour12: false, hour:"2-digit", minute:"2-digit", second:"2-digit"});
    row.innerHTML = `<span class="log-timestamp">[${timeStr}]</span> ${message.toUpperCase()}`;
    els.punchLogs.appendChild(row);
    els.punchLogs.scrollTop = els.punchLogs.scrollHeight;
}

// --- Chat Functions ---

function clearChatUI() {
    els.chatMessages.innerHTML = `
        <div class="chat-welcome">
            <div class="welcome-icon">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
            </div>
            <h3>CONNECTION ESTABLISHED</h3>
            <p>SECURE CHANNEL OPEN. BEGIN TRANSMISSION.</p>
        </div>
    `;
}

function addChatMessage(content, fromMe) {
    const welcome = els.chatMessages.querySelector('.chat-welcome');
    if (welcome) {
        welcome.remove();
    }

    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${fromMe ? 'from-me' : 'from-peer'}`;
    
    const bubbleDiv = document.createElement('div');
    bubbleDiv.className = 'message-bubble';
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';
    contentDiv.textContent = content;
    
    const timeDiv = document.createElement('span');
    timeDiv.className = 'message-time';
    const now = new Date();
    timeDiv.textContent = now.toLocaleTimeString(undefined, {hour: '2-digit', minute: '2-digit', hour12: false});
    
    bubbleDiv.appendChild(contentDiv);
    bubbleDiv.appendChild(timeDiv);
    messageDiv.appendChild(bubbleDiv);
    
    els.chatMessages.appendChild(messageDiv);
    els.chatMessages.scrollTop = els.chatMessages.scrollHeight;
}

async function handleChatSubmit(e) {
    e.preventDefault();
    const message = els.chatInput.value.trim();
    if (!message) return;
    
    els.sendBtn.disabled = true;
    
    try {
        const res = await fetch('/api/message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
        });
        
        if (!res.ok) throw new Error('Failed to send message');
        els.chatInput.value = '';
        els.chatInput.focus();
        
    } catch (err) {
        console.error('Failed to send message:', err);
        showToast('TRANSMISSION FAILED');
    } finally {
        els.sendBtn.disabled = false;
    }
}

// --- Interactions ---

async function handleConnect(e) {
    e.preventDefault();
    if (!state.isIpValid || !state.isPortValid) return;

    const ip = els.peerIpInput.value.trim();
    const port = parseInt(els.peerPortInput.value.trim(), 10);
    state.peerAddress = `${ip}:${port}`;

    // Capture optional username
    const username = els.usernameInput.value.trim();
    if (username) {
        state.username = username;
    }

    const btn = els.submitBtn;
    btn.innerText = "INITIATING...";
    btn.disabled = true;

    try {
        const res = await fetch('/api/connect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, port })
        });
        if (!res.ok) throw new Error();
        
        els.punchLogs.innerHTML = '';

    } catch (err) {
        showToast("CONNECTION FAILED TO START");
        btn.innerText = "INITIATE LINK SEQUENCE";
        btn.disabled = false;
    } 
}

// --- Disconnect Logic ---

async function handleDisconnect(e) {
    if(e) e.preventDefault();
    
    if(els.disconnectBtn) els.disconnectBtn.disabled = true;
    if(els.cancelPunchBtn) {
        els.cancelPunchBtn.disabled = true;
        els.cancelPunchBtn.innerText = "ABORTING...";
    }

    try {
        const res = await fetch('/api/disconnect', { method: 'POST' });
        if (!res.ok) throw new Error("Disconnect failed");
    } catch (err) {
        console.error('Disconnect failed:', err);
        showToast("FAILED TO DISCONNECT");
        
        if(els.disconnectBtn) els.disconnectBtn.disabled = false;
        if(els.cancelPunchBtn) {
            els.cancelPunchBtn.disabled = false;
            els.cancelPunchBtn.innerText = "ABORT SEQUENCE";
        }
    }
}

// --- Modal Logic ---
function toggleSasModal(e) {
    if (e) e.preventDefault();
    if (els.sasModal.classList.contains('active')) {
        els.sasModal.classList.remove('active');
    } else {
        els.sasModal.classList.add('active');
    }
}

// --- Validation & Utilities ---
function toggleSubmitButton() {
    els.submitBtn.disabled = !(state.isIpValid && state.isPortValid);
}

function showToast(message) {
    els.toastMsg.textContent = message.toUpperCase();
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
            showToast("PUBLIC IP COPIED");
        } catch (err) {
            console.error('Copy failed', err);
        }
        document.body.removeChild(textarea);
    }
}

function copyLocalToClipboard() {
    if (state.localAddress) {
        const textarea = document.createElement('textarea');
        textarea.value = state.localAddress;
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            showToast("LOCAL IP COPIED");
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

function parseIpPort(inputValue) {
    const match = inputValue.match(/^([0-9.]+):(\d+)$/);
    if (match) {
        const [, ip, port] = match;
        if (validators.ip(ip) && validators.port(port)) {
            els.peerIpInput.value = ip;
            els.peerPortInput.value = port;
            return true;
        }
    }
    return false;
}

function handleIpValidation(eventType) {
    const val = els.peerIpInput.value.trim();
    
    if (eventType === 'input' && val.includes(':')) {
        if (parseIpPort(val)) {
            handleIpValidation('input');
            handlePortValidation();
            return;
        }
    }
    
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
    if(els.copyLocalBtn) els.copyLocalBtn.addEventListener('click', copyLocalToClipboard);
    
    if(els.connectForm) els.connectForm.addEventListener('submit', handleConnect);
    
    if(els.peerIpInput) {
        els.peerIpInput.addEventListener('input', () => handleIpValidation('input'));
        els.peerIpInput.addEventListener('blur', () => handleIpValidation('blur'));
    }
    if(els.peerPortInput) els.peerPortInput.addEventListener('input', handlePortValidation);
    
    if(els.chatForm) els.chatForm.addEventListener('submit', handleChatSubmit);
    
    // Disconnect & Cancel
    if(els.disconnectBtn) els.disconnectBtn.addEventListener('click', handleDisconnect);
    if(els.cancelPunchBtn) els.cancelPunchBtn.addEventListener('click', handleDisconnect);

    // Modal
    if(els.verifyIdentityBtn) els.verifyIdentityBtn.addEventListener('click', toggleSasModal);
    if(els.closeSasBtn) els.closeSasBtn.addEventListener('click', toggleSasModal);
}

init();
