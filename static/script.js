// --- State Management ---
const state = {
    fullAddress: null,
    connectionStatus: 'disconnected',
    isIpValid: false,
    isPortValid: false
};

// --- DOM Elements ---
const els = {
    myIpDisplay: document.getElementById('myIpDisplay'),
    apiErrorMsg: document.getElementById('apiErrorMsg'),
    copyBtn: document.getElementById('copyBtn'),
    refreshBtn: document.getElementById('refreshBtn'),
    statusText: document.getElementById('statusText'),
    connectForm: document.getElementById('connectForm'),
    peerIpInput: document.getElementById('peerIp'),
    peerPortInput: document.getElementById('peerPort'),
    ipError: document.getElementById('ipError'),
    portError: document.getElementById('portError'),
    toast: document.getElementById('toast'),
    submitBtn: document.querySelector('#connectForm button')
};

// --- Initialization ---
async function init() {
    toggleSubmitButton();
    await fetchPublicInfo();
    await fetchState();
    setupEventListeners();

    // Poll status every 5 seconds
    setInterval(fetchState, 5000); 
}

// --- API Calls ---
async function fetchPublicInfo() {
    els.refreshBtn.classList.add('spin');
    els.refreshBtn.disabled = true;
    els.myIpDisplay.style.opacity = '0.5';

    try {
        const res = await fetch('/api/ip');
        if (!res.ok) throw new Error(`Server error: ${res.status}`);
        const data = await res.json();
        
        if (data.public_ip) {
            state.fullAddress = data.public_ip;
            renderMyInfo(true);
        } else {
            els.myIpDisplay.innerText = "Resolving IP...";
            els.copyBtn.style.display = 'none';
        }

    } catch (err) {
        console.error("Failed to fetch public IP:", err);
        renderMyInfo(false);
    } finally {
        setTimeout(() => {
            els.refreshBtn.classList.remove('spin');
            els.refreshBtn.disabled = false;
            els.myIpDisplay.style.opacity = '1';
        }, 500);
    }
}

async function fetchState() {
    try {
        const res = await fetch('/api/status');
        if (!res.ok) throw new Error("Server error");
        const data = await res.json();
        
        if (data.status) {
            state.connectionStatus = data.status;
            renderStatus();
        }
    } catch (err) {
        console.warn("Could not fetch status.");
    }
}

// --- UI Rendering ---
function renderMyInfo(success) {
    if (success && state.fullAddress) {
        els.myIpDisplay.innerText = state.fullAddress;
        els.myIpDisplay.classList.remove('error');
        els.apiErrorMsg.style.display = 'none';
        els.copyBtn.style.display = 'flex';
    } else if (!success) {
        els.myIpDisplay.innerText = "Connection Failed";
        els.myIpDisplay.classList.add('error');
        els.apiErrorMsg.innerText = "Could not reach GhostLink node.";
        els.apiErrorMsg.style.display = 'block';
        els.copyBtn.style.display = 'none';
    }
}

function renderStatus() {
    const s = state.connectionStatus;
    els.statusText.innerText = s.charAt(0).toUpperCase() + s.slice(1);
    
    const badge = document.getElementById('statusBadge');
    const dot = badge.querySelector('.status-dot');
    
    const isConnected = s.toLowerCase() === 'connected';
    const isPunching = s.toLowerCase() === 'punching';
    
    if (isConnected) {
        setBadgeColor('var(--success)', 'rgba(16, 185, 129, 0.1)', 'rgba(16, 185, 129, 0.2)');
    } else if (isPunching) {
        setBadgeColor('#f59e0b', 'rgba(245, 158, 11, 0.1)', 'rgba(245, 158, 11, 0.2)');
    } else {
        setBadgeColor('var(--danger)', 'rgba(239, 68, 68, 0.1)', 'rgba(239, 68, 68, 0.2)');
    }

    function setBadgeColor(color, bg, border) {
        dot.style.backgroundColor = color;
        dot.style.boxShadow = `0 0 8px ${color}`;
        badge.style.color = color;
        badge.style.background = bg;
        badge.style.borderColor = border;
    }
}

function toggleSubmitButton() {
    els.submitBtn.disabled = !(state.isIpValid && state.isPortValid);
}

function showToast(message) {
    // Update text node inside toast (preserving the SVG icon)
    els.toast.childNodes[2].textContent = ` ${message}`;
    els.toast.classList.add('show');
    setTimeout(() => els.toast.classList.remove('show'), 2500);
}

// --- Validation Logic ---
const validators = {
    ip: (ip) => /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip),
    port: (port) => {
        const p = parseInt(port, 10);
        return !isNaN(p) && p > 0 && p <= 65535;
    }
};

function handleIpValidation(eventType) {
    const val = els.peerIpInput.value.trim();
    const isValid = validators.ip(val);
    state.isIpValid = isValid;

    if (isValid) {
        els.peerIpInput.classList.remove('error');
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
        els.peerPortInput.classList.remove('error');
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

function copyToClipboard() {
    if (!state.fullAddress) return;
    navigator.clipboard.writeText(state.fullAddress).then(() => {
        showToast("Copied to clipboard");
    }).catch(err => console.error("Clipboard error:", err));
}

// --- MAIN CONNECT LOGIC ---
async function handleConnect(e) {
    e.preventDefault();
    if (!state.isIpValid || !state.isPortValid) return;

    const ip = els.peerIpInput.value.trim();
    const port = parseInt(els.peerPortInput.value.trim(), 10);
    
    // UI Loading State
    const btn = els.submitBtn;
    const originalText = btn.innerText;
    btn.innerText = "Initiating...";
    btn.disabled = true;

    try {
        console.log(`Sending payload: {"ip": "${ip}", "port": ${port}}`);

        const res = await fetch('/api/connect', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ip, port })
        });

        if (!res.ok) {
            throw new Error(`Server returned ${res.status}`);
        }

        // If successful
        showToast("Connection Initiated");
        
        // Optionally trigger an immediate status refresh
        setTimeout(fetchState, 500);

    } catch (err) {
        console.error("Connection request failed:", err);
        alert("Failed to initiate connection. Check console for details.");
    } finally {
        // Restore button state
        btn.innerText = originalText;
        btn.disabled = false;
    }
}

// --- Event Listeners ---
function setupEventListeners() {
    if(els.copyBtn) els.copyBtn.addEventListener('click', copyToClipboard);
    if(els.refreshBtn) els.refreshBtn.addEventListener('click', fetchPublicInfo);

    els.connectForm.addEventListener('submit', handleConnect);
    els.peerIpInput.addEventListener('input', () => handleIpValidation('input'));
    els.peerIpInput.addEventListener('blur', () => handleIpValidation('blur'));
    els.peerPortInput.addEventListener('input', handlePortValidation);
}

// Run
init();
