use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::{RwLock, broadcast, mpsc};

/// A thread safe wrapper around the application state.
///
/// This alias allows multiple parts of the application (e.g., the web server
/// and the P2P controller) to share and modify the state concurrently.
pub type SharedState = Arc<RwLock<AppState>>;

/// Represents the core runtime state of the GhostLink application.
///
/// This struct serves as the "source of truth" for the application's status.
/// It holds network information (IPs, NAT type) and connectivity status.
///
/// # Architecture
/// This struct is shared between:
/// 1. The **Controller**: Handles P2P logic, STUN resolution, and connection management.
/// 2. The **Web Server**: Serves the UI and streams state updates to the frontend via SSE/WebSocket.
///
/// # Serialization
/// Fields marked with `#[serde(skip)]` are excluded from JSON serialization
/// because they are runtime control channels, not persistent state data.
#[derive(Debug, Serialize, Clone)]
pub struct AppState {
    /// The public IP address and port of this node, as seen by the STUN server.
    ///
    /// This is `None` initially and is populated once STUN resolution succeeds.
    pub public_ip: Option<SocketAddr>,

    /// The type of NAT (Network Address Translation) detected by the router.
    /// This determines the compatibility of P2P connections.
    pub nat_type: NatType,

    /// The current operational status of the P2P node.
    pub status: Status,

    /// The IP address of the peer we are connecting to or are connected with.
    ///
    /// This is `None` until a valid handshake is initiated.
    pub peer_ip: Option<SocketAddr>,

    /// Channel to send commands *to* the background controller task.
    ///
    /// Used by the web server to trigger actions like "Connect".
    #[serde(skip)]
    cmd_tx: mpsc::Sender<Command>,

    /// Channel to broadcast state change events *to* the web UI.
    ///
    /// The web server subscribes to this to push updates to the frontend.
    #[serde(skip)]
    event_tx: broadcast::Sender<AppEvent>,
}

impl AppState {
    /// Creates a new instance of the application state with default values.
    ///
    /// # Arguments
    ///
    /// * `cmd_tx` - Channel for sending commands to the controller.
    /// * `event_tx` - Channel for broadcasting events to the UI.
    pub fn new(cmd_tx: mpsc::Sender<Command>, event_tx: broadcast::Sender<AppEvent>) -> Self {
        Self {
            public_ip: None,
            nat_type: NatType::default(),
            status: Status::default(),
            peer_ip: None,
            cmd_tx,
            event_tx,
        }
    }

    /// Returns a reference to the command sender channel.
    pub fn cmd_tx(&self) -> &mpsc::Sender<Command> {
        &self.cmd_tx
    }

    /// Creates a new subscriber for the event broadcast channel.
    pub fn subscribe_events(&self) -> broadcast::Receiver<AppEvent> {
        self.event_tx.subscribe()
    }

    // -- State Mutators --
    // These methods update the state and automatically broadcast the change to the UI.

    /// Updates the public IP address and notifies listeners.
    pub fn set_public_ip(
        &mut self,
        addr: SocketAddr,
        message: Option<String>,
        timeout: Option<u64>,
    ) {
        self.public_ip = Some(addr);
        self.broadcast_status_change(message, timeout);
    }

    /// Updates the NAT type and notifies listeners.
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

    /// Updates the connection status and notifies listeners.
    pub fn set_status(&mut self, status: Status, message: Option<String>, timeout: Option<u64>) {
        self.status = status;
        self.broadcast_status_change(message, timeout);
    }

    /// Updates the peer's IP address and notifies listeners.
    pub fn set_peer_ip(&mut self, addr: SocketAddr, message: Option<String>, timeout: Option<u64>) {
        self.peer_ip = Some(addr);
        self.broadcast_status_change(message, timeout);
    }

    /// Broadcasts the current state to all active listeners (e.g., Web UI).
    ///
    /// This constructs an `AppEvent` based on the current `status` and sends it
    /// via the `event_tx` channel.
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

    /// Explicitly broadcasts a new chat message to the UI.
    pub fn add_message(&self, content: String, from_me: bool) {
        let _ = self.event_tx.send(AppEvent::Message { content, from_me });
    }

    /// General helper for other updates if needed
    fn broadcast_event(&self, event: AppEvent) {
        let _ = self.event_tx.send(event);
    }
}

/// Represents the NAT (Network Address Translation) type of the network.
///
/// This classification helps determine if a direct P2P connection is feasible.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Default)]
pub enum NatType {
    /// NAT type has not yet been determined (STUN pending).
    #[default]
    Unknown,
    /// Cone NAT: The router uses a consistent external port for internal clients.
    /// This is **favorable** for P2P hole punching.
    Cone,
    /// Symmetric NAT: The router assigns different external ports for different destinations.
    /// This is **unfavorable** and difficult for P2P hole punching.
    Symmetric,
}

/// Represents a distinct event sent from the server to the Web UI.
///
/// The structure of the event changes based on the application's connection status.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AppEvent {
    /// The application is idle or disconnected.
    ///
    /// Payload includes the full `AppState` to ensure the UI is fully synchronized.
    Disconnected {
        state: AppState,
    },

    /// The application is actively trying to punch a hole through the NAT.
    Punching {
        /// Time remaining (in seconds) for the handshake attempt.
        timeout: Option<u64>,
        /// Logs (e.g., hole punched/ACK received).
        message: Option<String>,
    },

    /// A P2P connection has been successfully established.
    Connected {
        /// Informational message from the peer or system.
        message: Option<String>,
    },

    Message {
        content: String,
        from_me: bool,
    },
}

/// Represents the high level connection state of the P2P node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Status {
    /// The node is idle and waiting for user input or STUN resolution.
    #[default]
    Disconnected,

    /// The node is actively performing the hole punching handshake.
    Punching,

    /// The node has successfully established a P2P session with a peer.
    Connected,
}

/// Commands sent from the Web Interface (or other drivers) to the Controller.
#[derive(Debug)]
pub enum Command {
    /// Instructs the controller to initiate a connection attempt to the configured peer.
    ConnectPeer,

    SendMessage(String),
}
