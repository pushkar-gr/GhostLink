use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::{RwLock, broadcast, mpsc};

/// Thread-safe wrapper for application state.
///
/// Allows the web server and network controller to share state concurrently.
pub type SharedState = Arc<RwLock<AppState>>;

/// Core application state.
///
/// Holds network information and connectivity status.
///
/// Shared between:
/// - Network controller (manages P2P, STUN, connections)
/// - Web server (serves UI and streams updates via SSE)
///
/// Fields marked `#[serde(skip)]` are excluded from JSON serialization
/// as they're internal control channels.
#[derive(Debug, Serialize, Clone)]
pub struct AppState {
    /// Local IP and port (for LAN connections).
    pub local_ip: Option<SocketAddr>,

    /// Public IP and port (resolved via STUN).
    pub public_ip: Option<SocketAddr>,

    /// NAT type detected by the router.
    pub nat_type: NatType,

    /// Current connection status.
    pub status: Status,

    /// Peer's IP address.
    pub peer_ip: Option<SocketAddr>,

    /// Channel for sending commands to the controller.
    #[serde(skip)]
    cmd_tx: mpsc::Sender<Command>,

    /// Channel for broadcasting state changes to the UI.
    #[serde(skip)]
    event_tx: broadcast::Sender<AppEvent>,
}

impl AppState {
    /// Creates a new application state with default values.
    ///
    /// # Arguments
    ///
    /// * `cmd_tx` - Channel for sending commands to controller
    /// * `event_tx` - Channel for broadcasting events to UI
    pub fn new(cmd_tx: mpsc::Sender<Command>, event_tx: broadcast::Sender<AppEvent>) -> Self {
        Self {
            local_ip: None,
            public_ip: None,
            nat_type: NatType::default(),
            status: Status::default(),
            peer_ip: None,
            cmd_tx,
            event_tx,
        }
    }

    /// Returns the command sender channel.
    pub fn cmd_tx(&self) -> &mpsc::Sender<Command> {
        &self.cmd_tx
    }

    /// Creates a new event subscriber.
    pub fn subscribe_events(&self) -> broadcast::Receiver<AppEvent> {
        self.event_tx.subscribe()
    }

    // -- State Setters --
    // These methods update state and broadcast changes to listeners.

    /// Updates local IP and notifies listeners.
    pub fn set_local_ip(
        &mut self,
        addr: SocketAddr,
        message: Option<String>,
        timeout: Option<u64>,
    ) {
        self.local_ip = Some(addr);
        self.broadcast_status_change(message, timeout);
    }

    /// Updates public IP and notifies listeners.
    pub fn set_public_ip(
        &mut self,
        addr: SocketAddr,
        message: Option<String>,
        timeout: Option<u64>,
    ) {
        self.public_ip = Some(addr);
        self.broadcast_status_change(message, timeout);
    }

    /// Updates NAT type and notifies listeners.
    #[allow(dead_code)]
    pub fn set_nat_type(
        &mut self,
        nat_type: NatType,
        message: Option<String>,
        timeout: Option<u64>,
    ) {
        self.nat_type = nat_type;
        self.broadcast_status_change(message, timeout);
    }

    /// Updates connection status and notifies listeners.
    pub fn set_status(&mut self, status: Status, message: Option<String>, timeout: Option<u64>) {
        self.status = status;
        self.broadcast_status_change(message, timeout);
    }

    /// Updates peer IP and notifies listeners.
    pub fn set_peer_ip(&mut self, addr: SocketAddr, message: Option<String>, timeout: Option<u64>) {
        self.peer_ip = Some(addr);
        self.broadcast_status_change(message, timeout);
    }

    /// Broadcasts current state to all active listeners.
    ///
    /// Constructs an event based on the current status and sends it
    /// via the event channel.
    fn broadcast_status_change(&self, message: Option<String>, timeout: Option<u64>) {
        let event = match self.status {
            // When disconnected, we send the full state so the UI can sync up.
            Status::Disconnected => AppEvent::Disconnected {
                state: self.clone(),
            },
            // During punching, we primarily send progress updates/timeouts.
            Status::Punching => AppEvent::Punching { timeout, message },
            // When connected, we send status messages.
            Status::Connected => AppEvent::Connected { message },
        };
        self.broadcast_event(event);
    }

    /// Broadcasts a chat message to the UI.
    pub fn add_message(&self, content: String, from_me: bool) {
        let _ = self.event_tx.send(AppEvent::Message { content, from_me });
    }

    /// Broadcasts an event to the UI.
    fn broadcast_event(&self, event: AppEvent) {
        let _ = self.event_tx.send(event);
    }
}

/// NAT (Network Address Translation) type.
///
/// Determines if direct P2P connections are possible.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Default)]
pub enum NatType {
    /// NAT type not yet determined.
    #[default]
    Unknown,
    /// Cone NAT: Uses consistent external port (P2P-friendly).
    Cone,
    /// Symmetric NAT: Uses different external ports per destination (P2P-difficult).
    Symmetric,
}

/// Event sent from server to UI.
///
/// Structure varies based on connection status.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AppEvent {
    /// Application is idle or disconnected.
    ///
    /// Includes full state for UI synchronization.
    Disconnected {
        state: AppState,
    },

    /// Attempting NAT hole punching.
    Punching {
        /// Time remaining for handshake attempt (seconds).
        timeout: Option<u64>,
        /// Log messages.
        message: Option<String>,
    },

    /// P2P connection established.
    Connected {
        /// System or peer message.
        message: Option<String>,
    },

    Message {
        content: String,
        from_me: bool,
    },
}

/// Connection state of the P2P node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Status {
    /// Idle, waiting for user input.
    #[default]
    Disconnected,

    /// Performing hole punching handshake.
    Punching,

    /// P2P session established.
    Connected,
}

/// Commands from Web UI to Controller.
#[derive(Debug)]
pub enum Command {
    /// Initiate connection to configured peer.
    ConnectPeer,

    /// Sends a message
    SendMessage(String),
}
