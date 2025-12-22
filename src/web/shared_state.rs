use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::{RwLock, broadcast, mpsc};

/// A thread-safe wrapper around the application state.
pub type SharedState = Arc<RwLock<AppState>>;

/// Represents the core runtime state of the GhostLink application.
///
/// This struct holds data that needs to be shared across the web and controller.
#[derive(Debug, Serialize)]
pub struct AppState {
    /// The public IP address and port of this node, as seen by the STUN server.
    ///
    /// This is `None` until the STUN resolution completes.
    pub public_ip: Option<SocketAddr>,

    /// The current connectivity status of the P2P node.
    pub status: Status,

    /// IP address of peer client is connecting to.
    ///
    /// This is `None` until client clicks connect with valid address.
    pub peer_ip: Option<SocketAddr>,

    /// A MPSC channel to send message to controller.
    #[serde(skip)]
    pub cmd_tx: mpsc::Sender<Command>,

    /// A broadcast channel to send updates to web server.
    #[serde(skip)]
    pub event_tx: broadcast::Sender<AppEvent>,
}

impl AppState {
    /// Creates a new instance of the application state.
    ///
    /// # Arguments
    ///
    /// * `public_ip` - The initial public IP (usually `None` at startup).
    /// * `status` - The initial status (usually `Status::Disconnected`).
    /// * `peer_ip` - The IP of connecting peer.
    /// * `cmd_tx` - MPSC channel to send commands to controller.
    /// * `event_tx` - broadcast channel to send updates to UI.
    pub fn new(
        public_ip: Option<SocketAddr>,
        status: Status,
        peer_ip: Option<SocketAddr>,
        cmd_tx: mpsc::Sender<Command>,
        event_tx: broadcast::Sender<AppEvent>,
    ) -> Self {
        Self {
            public_ip,
            status,
            peer_ip,
            cmd_tx,
            event_tx,
        }
    }
}

/// Represents
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AppEvent {
    Disconnected {
        public_ip: Option<SocketAddr>,
    },

    Punching {
        timeout: Option<u64>,
        message: Option<String>,
    },

    Connected {
        message: Option<String>,
    },
}

/// Represents the connection state of the P2P node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Status {
    /// The node is idle and not connected to any peer.
    Disconnected,

    /// The node is actively attempting to initiate a connection (hole punching)
    /// with a peer.
    Punching,

    /// A direct P2P connection has been successfully established.
    Connected,
}

/// Represents a command sent to controller
#[derive(Debug)]
pub enum Command {
    /// Command sent from web server to controller to connect to a pper.
    ConnectPeer,
}
