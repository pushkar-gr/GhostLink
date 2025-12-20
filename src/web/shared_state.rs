use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;

/// A thread-safe wrapper around the application state.
pub type SharedState = Arc<RwLock<AppState>>;

/// Represents the core runtime state of the GhostLink application.
///
/// This struct holds data that needs to be shared across the web and controller.
#[derive(Debug, Clone, Serialize)]
pub struct AppState {
    /// The public IP address and port of this node, as seen by the STUN server.
    ///
    /// This is `None` until the STUN resolution completes.
    pub public_ip: Option<SocketAddr>,

    /// The current connectivity status of the P2P node.
    pub status: Status,

    /// IP address of peer client is connecting to
    ///
    /// This is `None` until client clicks connect with valid address
    pub peer_ip: Option<SocketAddr>,
    /// To store logs
    pub logs: Vec<String>,
}

impl AppState {
    /// Creates a new instance of the application state.
    ///
    /// # Arguments
    ///
    /// * `public_ip` - The initial public IP (usually `None` at startup).
    /// * `status` - The initial status (usually `Status::Disconnected`).
    pub fn new(public_ip: Option<SocketAddr>, status: Status, peer_ip: Option<SocketAddr>) -> Self {
        Self {
            public_ip,
            status,
            peer_ip,
            logs: Vec::new(),
        }
    }
}

/// Represents the connection state of the P2P node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Status {
    /// The node is idle and not connected to any peer.
    Disconnected,

    /// The node is actively attempting to initiate a connection (hole punching)
    /// with a peer.
    _Punching,

    /// A direct P2P connection has been successfully established.
    Connected,
}
