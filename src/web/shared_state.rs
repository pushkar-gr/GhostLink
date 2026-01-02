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

    // --- ENCRYPTION STATE ---
    /// The Short Authentication String (SAS) fingerprint for manual verification.
    pub fingerprint: Option<String>,
    /// The name of the negotiated encryption algorithm (e.g., "ChaCha20-Poly1305").
    pub encryption_algo: Option<String>,
    // ------------------------
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
            fingerprint: None,
            encryption_algo: None,
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
    #[allow(dead_code)]
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

    /// Updates security details for current session.
    /// Called by handshake module upon successful key exchange.
    pub fn set_security_info(&mut self, fingerprint: String, algorithm: String) {
        self.fingerprint = Some(fingerprint);
        self.encryption_algo = Some(algorithm);
        // Note: Does not broadcast immediately.
        // Handshake typically calls set_status(Connected) right after,
        // which triggers broadcast with this new data included.
    }

    /// Broadcasts current state to all active listeners.
    ///
    /// Constructs an event based on the current status and sends it
    /// via the event channel.
    fn broadcast_status_change(&self, message: Option<String>, timeout: Option<u64>) {
        let event = match self.status {
            // When disconnected, sends the full state.
            Status::Disconnected => AppEvent::Disconnected {
                state: self.clone(),
                message,
            },
            // During punching, sends progress updates and timeouts.
            Status::Punching => AppEvent::Punching { timeout, message },
            // When connected, sends status messages AND security info.
            Status::Connected => AppEvent::Connected {
                message,
                fingerprint: self.fingerprint.clone(),
                encryption_algo: self.encryption_algo.clone(),
            },
        };
        self.broadcast_event(event);
    }

    /// Broadcasts a chat message to the UI.
    pub fn add_message(&self, content: String, from_me: bool) {
        let _ = self.event_tx.send(AppEvent::Message { content, from_me });
    }

    /// Clears the chat history in the UI.
    pub fn clear_chat(&self) {
        let _ = self.event_tx.send(AppEvent::ClearChat);
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
#[allow(dead_code)]
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
    Disconnected {
        /// Full state for UI synchronization.
        state: AppState,
        /// Messages.
        message: Option<String>,
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
        /// SAS Fingerprint for UI verification
        fingerprint: Option<String>,
        /// Algorithm used
        encryption_algo: Option<String>,
    },

    Message {
        content: String,
        from_me: bool,
    },

    /// Clear chat history.
    ClearChat,
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

    /// Disconnect from current peer
    Disconnect,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_state() -> AppState {
        let (cmd_tx, _cmd_rx) = mpsc::channel(32);
        let (event_tx, _event_rx) = broadcast::channel(32);
        AppState::new(cmd_tx, event_tx)
    }

    #[test]
    fn test_app_state_initialization() {
        let state = create_test_state();

        assert_eq!(state.local_ip, None);
        assert_eq!(state.public_ip, None);
        assert_eq!(state.nat_type, NatType::Unknown);
        assert_eq!(state.status, Status::Disconnected);
        assert_eq!(state.peer_ip, None);
        assert_eq!(state.fingerprint, None);
        assert_eq!(state.encryption_algo, None);
    }

    #[test]
    fn test_set_local_ip() {
        let mut state = create_test_state();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);

        state.set_local_ip(addr, Some("Local IP set".into()), None);

        assert_eq!(state.local_ip, Some(addr));
    }

    #[test]
    fn test_set_public_ip() {
        let mut state = create_test_state();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 5678);

        state.set_public_ip(addr, Some("Public IP resolved".into()), None);

        assert_eq!(state.public_ip, Some(addr));
    }

    #[test]
    fn test_set_nat_type() {
        let mut state = create_test_state();

        state.set_nat_type(NatType::Cone, Some("NAT detected".into()), None);
        assert_eq!(state.nat_type, NatType::Cone);

        state.set_nat_type(NatType::Symmetric, None, None);
        assert_eq!(state.nat_type, NatType::Symmetric);
    }

    #[test]
    fn test_set_status() {
        let mut state = create_test_state();

        state.set_status(Status::Punching, Some("Connecting...".into()), Some(30));
        assert_eq!(state.status, Status::Punching);

        state.set_status(Status::Connected, Some("Connected".into()), None);
        assert_eq!(state.status, Status::Connected);
    }

    #[test]
    fn test_set_peer_ip() {
        let mut state = create_test_state();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9999);

        state.set_peer_ip(addr, Some("Peer set".into()), None);

        assert_eq!(state.peer_ip, Some(addr));
    }

    #[test]
    fn test_set_security_info() {
        let mut state = create_test_state();

        state.set_security_info("abcd1234".to_string(), "ChaCha20-Poly1305".to_string());

        assert_eq!(state.fingerprint, Some("abcd1234".to_string()));
        assert_eq!(state.encryption_algo, Some("ChaCha20-Poly1305".to_string()));
    }

    #[tokio::test]
    async fn test_event_subscription() {
        let (cmd_tx, _cmd_rx) = mpsc::channel(32);
        let (event_tx, _event_rx) = broadcast::channel(32);
        let state = AppState::new(cmd_tx, event_tx);

        let mut rx = state.subscribe_events();

        // Send a test event
        state.add_message("Test message".to_string(), true);

        // Should receive the event
        let event = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;

        assert!(event.is_ok());
    }

    #[tokio::test]
    async fn test_command_channel() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
        let (event_tx, _event_rx) = broadcast::channel(32);
        let state = AppState::new(cmd_tx.clone(), event_tx);

        // Send a command
        state.cmd_tx().send(Command::ConnectPeer).await.unwrap();

        // Should receive the command
        let cmd = cmd_rx.recv().await;
        assert!(cmd.is_some());
    }

    #[test]
    fn test_nat_type_equality() {
        assert_eq!(NatType::Unknown, NatType::Unknown);
        assert_eq!(NatType::Cone, NatType::Cone);
        assert_eq!(NatType::Symmetric, NatType::Symmetric);

        assert_ne!(NatType::Unknown, NatType::Cone);
        assert_ne!(NatType::Cone, NatType::Symmetric);
    }

    #[test]
    fn test_status_equality() {
        assert_eq!(Status::Disconnected, Status::Disconnected);
        assert_eq!(Status::Punching, Status::Punching);
        assert_eq!(Status::Connected, Status::Connected);

        assert_ne!(Status::Disconnected, Status::Punching);
        assert_ne!(Status::Punching, Status::Connected);
    }

    #[test]
    fn test_clear_chat() {
        let state = create_test_state();

        // Should not panic
        state.clear_chat();
    }

    #[test]
    fn test_add_message() {
        let state = create_test_state();

        // Should not panic
        state.add_message("Hello".to_string(), true);
        state.add_message("World".to_string(), false);
    }
}
