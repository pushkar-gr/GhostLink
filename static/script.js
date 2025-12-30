const state = {
    fullAddress: null,
    localAddress: null,
    peerAddress: null,
    natType: 'SCANNING',
    connectionStatus: 'disconnected',
    isIpValid: false,
    isPortValid: false,
    sseSource: null,
    punchInterval: null
};

const els = {
    viewHome: document.getElementById('view-home'),
    viewPunching: document.getElementById('view-punching'),
    viewConnected: document.getElementById('view-connected'),
    statusText: document.getElementById('statusText'),
    statusDot: document.querySelector('.status-dot'),
    myIp: document.getElementById('myIpDisplay'),
    myLocalIp: document.getElementById('myLocalIpDisplay'),
    natType: document.getElementById('natTypeDisplay'),
    peerIpInput: document.getElementById('peerIp'),
    peerPortInput: document.getElementById('peerPort'),
    connectForm: document.getElementById('connectForm'),
    submitBtn: document.querySelector('#connectForm button'),
    punchTimer: document.getElementById('punchTimerDisplay'),
    punchLogs: document.getElementById('punchLogs'),
    cancelBtn: document.getElementById('cancelPunchBtn'),
    chatMessages: document.getElementById('chatMessages'),
    chatPeerIp: document.getElementById('chatPeerIp'),
    chatForm: document.getElementById('chatForm'),
    chatInput: document.getElementById('chatInput'),
    disconnectBtn: document.getElementById('disconnectBtn'),
    toast: document.getElementById('toast'),
    ipError: document.getElementById('ipError'),
    portError: document.getElementById('portError')
};

async function init() {
    validateForm();
    await fetchState();
    connectSSE();
    setupEvents();
}

async function fetchState() {
    try {
        const res = await fetch('/api/state');
        if (!res.ok) throw new Error();
        const json = await res.json();
        if (json.state) syncState(json.state);
    } catch (e) {
        showToast("SYSTEM_ERR: STATE_FETCH_FAIL");
    }
}

function syncState(data) {
    if (data.public_ip) {
        state.fullAddress = data.public_ip;
        els.myIp.textContent = data.public_ip;
    }
    if (data.local_ip) {
        state.localAddress = data.local_ip;
        els.myLocalIp.textContent = data.local_ip;
    }
    if (data.nat_type) {
        state.natType = data.nat_type;
        els.natType.textContent = data.nat_type.toUpperCase();
    }
    if (data.status) handleStatusChange(data.status, data);
}

function handleStatusChange(statusStr, data = {}) {
    const status = (statusStr || 'DISCONNECTED').toUpperCase();
    state.connectionStatus = status.toLowerCase();

    clearInterval(state.punchInterval);

    els.viewHome.classList.remove('active');
    els.viewPunching.classList.remove('active');
    els.viewConnected.classList.remove('active');

    els.statusText.textContent = status;

    els.cancelBtn.disabled = false;
    els.cancelBtn.textContent = "ABORT SEQUENCE";

    if (status === 'PUNCHING') {
        els.viewPunching.classList.add('active');
        els.statusDot.style.background = 'var(--warning)';
        els.statusDot.style.boxShadow = '0 0 10px var(--warning)';
        startMatchmakingTimer(data.timeout || 60);
        if(data.message) addLog(data.message);
    } else if (status === 'CONNECTED') {
        els.viewConnected.classList.add('active');
        els.statusDot.style.background = 'var(--success)';
        els.statusDot.style.boxShadow = '0 0 10px var(--success)';
        els.chatPeerIp.textContent = state.peerAddress || "UNKNOWN";
        if(data.message) addChatMessage("SYSTEM", data.message);
    } else {
        els.viewHome.classList.add('active');
        els.statusDot.style.background = 'var(--danger)';
        els.statusDot.style.boxShadow = '0 0 10px var(--danger)';
        
        els.submitBtn.disabled = !(state.isIpValid && state.isPortValid);
        els.submitBtn.textContent = "INITIATE LINK SEQUENCE";
        
        if (data.message) showToast(data.message);
    }
}

function startMatchmakingTimer(seconds) {
    let left = seconds;
    updateTimerDisplay(left);
    state.punchInterval = setInterval(() => {
        left--;
        updateTimerDisplay(left);
        if (left <= 0) clearInterval(state.punchInterval);
    }, 1000);
}

function updateTimerDisplay(seconds) {
    const m = Math.floor(seconds / 60).toString().padStart(2, '0');
    const s = (seconds % 60).toString().padStart(2, '0');
    els.punchTimer.textContent = `${m}:${s}`;
}

function connectSSE() {
    if (state.sseSource) return;
    state.sseSource = new EventSource('/api/events');
    state.sseSource.onmessage = (e) => {
        const data = JSON.parse(e.data);
        if (data.status === 'MESSAGE') {
            addChatMessage(data.from_me ? "ME" : "PEER", data.content);
        } else if (data.status) {
            handleStatusChange(data.status, data);
        }
    };
}

function addLog(msg) {
    const line = document.createElement('div');
    line.className = 'log-line';
    line.textContent = `> ${msg.toUpperCase()}`;
    els.punchLogs.appendChild(line);
    els.punchLogs.scrollTop = els.punchLogs.scrollHeight;
}

function addChatMessage(sender, msg) {
    const row = document.createElement('div');
    row.className = `msg-line ${sender === 'ME' ? 'me' : 'peer'}`;
    row.innerHTML = `<span class="msg-prefix">[${sender}]</span> <span>${msg}</span>`;
    els.chatMessages.appendChild(row);
    els.chatMessages.scrollTop = els.chatMessages.scrollHeight;
}

function validateForm() {
    const ipVal = els.peerIpInput.value;
    const portVal = parseInt(els.peerPortInput.value);
    
    state.isIpValid = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ipVal);
    state.isPortValid = portVal > 0 && portVal < 65536;

    els.ipError.style.display = state.isIpValid || ipVal === '' ? 'none' : 'block';
    els.portError.style.display = state.isPortValid || isNaN(portVal) ? 'none' : 'block';
    
    els.submitBtn.disabled = !(state.isIpValid && state.isPortValid);
}

function setupEvents() {
    els.peerIpInput.addEventListener('input', validateForm);
    els.peerPortInput.addEventListener('input', validateForm);

    document.getElementById('copyBtn').addEventListener('click', () => {
        navigator.clipboard.writeText(state.fullAddress);
        showToast("PUBLIC_IP_COPIED_TO_CLIPBOARD");
    });

    document.getElementById('copyLocalBtn').addEventListener('click', () => {
        navigator.clipboard.writeText(state.localAddress);
        showToast("LOCAL_IP_COPIED_TO_CLIPBOARD");
    });

    els.connectForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const ip = els.peerIpInput.value;
        const port = parseInt(els.peerPortInput.value);
        state.peerAddress = `${ip}:${port}`;
        els.submitBtn.disabled = true;
        els.submitBtn.textContent = "INITIALIZING SEQUENCE...";
        els.punchLogs.innerHTML = '';
        
        try {
            await fetch('/api/connect', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ ip, port })
            });
        } catch(err) {
            showToast("INIT_FAILED");
            els.submitBtn.disabled = false;
        }
    });

    els.cancelBtn.addEventListener('click', async (e) => {
        e.preventDefault(); 
        els.cancelBtn.disabled = true;
        els.cancelBtn.textContent = "ABORTING...";
        
        try {
            await fetch('/api/disconnect', { method: 'POST' });
        } catch (err) {
            showToast("ABORT_FAILED");
            els.cancelBtn.textContent = "ABORT SEQUENCE";
            els.cancelBtn.disabled = false;
        }
    });

    els.disconnectBtn.addEventListener('click', async () => {
        await fetch('/api/disconnect', { method: 'POST' });
    });

    els.chatForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const msg = els.chatInput.value.trim();
        if(!msg) return;
        els.chatInput.value = '';
        await fetch('/api/message', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ message: msg })
        });
    });
}

function showToast(msg) {
    const t = els.toast;
    t.querySelector('.toast-msg').textContent = msg;
    t.classList.add('show');
    
    if (t.hideTimeout) clearTimeout(t.hideTimeout);
    
    t.hideTimeout = setTimeout(() => {
        t.classList.remove('show');
    }, 3000);
}

init();