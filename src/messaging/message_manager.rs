use super::{
    super::web::shared_state::{SharedState, Status},
    handshake,
};
use anyhow::{Result, bail};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};
use tokio_kcp::{KcpConfig, KcpNoDelayConfig, KcpStream};
use tracing::{error, info};

/// Manages the lifecycle of a P2P connection, handling the transition from raw UDP to reliable KCP.
///
/// This struct is the central controller for:
/// 1. **Handshaking**: coordinating UDP hole punching via the `handshake` module.
/// 2. **Upgrading**: Converting the raw UDP socket into a reliable `KcpStream` without losing the underlying connection.
/// 3. **Teardown**: Safely closing the KCP stream while preserving the shared socket if needed.
#[derive(Debug)]
pub struct MessageManager {
    /// The shared UDP socket used for both initial discovery and the eventual KCP stream.
    client_socket: Arc<UdpSocket>,
    /// Shared application state for updating UI/Status.
    state: SharedState,
    /// The address of the connected peer. Only set after a successful handshake.
    peer_addr: Option<SocketAddr>,
    /// The active reliable stream. None until `upgrade_to_kcp` is called.
    kcp_stream: Option<KcpStream>,
}

impl MessageManager {
    /// Creates a new `MessageManager` in a disconnected state.
    ///
    /// # Arguments
    ///
    /// * `client_socket` - The local UDP socket bound to a specific port.
    /// * `state` - Reference to the application's shared state store.
    pub fn new(client_socket: Arc<UdpSocket>, state: SharedState) -> Self {
        Self {
            client_socket,
            state,
            peer_addr: None,
            kcp_stream: None,
        }
    }

    /// Initiates the connection handshake with a target peer.
    ///
    /// This method blocks (async) until the handshake succeeds or times out.
    /// It handles the `Punching` -> `Connected` state transitions in the shared state.
    ///
    /// # Arguments
    ///
    /// * `peer_addr` - The public IP/Port of the target peer.
    /// * `timeout_secs` - Max time to wait for the handshake protocol to complete.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Handshake succeeded; `self.peer_addr` is set.
    /// * `Err` - Handshake failed; State reset to `Disconnected`.
    pub async fn handshake(&mut self, peer_addr: SocketAddr, timeout_secs: u64) -> Result<()> {
        info!("Initializing MessageManager for peer {}", peer_addr);

        match handshake::handshake(
            self.client_socket.clone(),
            peer_addr,
            self.state.clone(),
            timeout_secs,
        )
        .await
        {
            Ok(_) => {
                info!("Handshake successful. MessageManager active.");
                self.peer_addr = Some(peer_addr);
                Ok(())
            }
            Err(e) => {
                error!("Handshake failed: {}", e);

                self.state.write().await.set_status(
                    Status::Disconnected,
                    Some(format!("Connection failed: {}", e)),
                    None,
                );
                bail!(e);
            }
        }
    }

    /// Upgrades the existing raw UDP connection to a reliable KCP stream.
    ///
    /// This utilizes "Turbo Mode" configuration for low latency:
    /// - NoDelay: enabled
    /// - Update Interval: 10ms
    /// - Resend: 2 (fast retransmission)
    /// - No Congestion Control (NC): enabled
    /// - Windows: 1024 packets (allows higher throughput)
    /// - MTU: 1400 (safe default for UDP)
    ///
    /// # Errors
    ///
    /// Returns an error if the handshake has not been performed yet (`peer_addr` is None)
    /// or if the socket cloning fails.
    pub async fn upgrade_to_kcp(&mut self) -> Result<()> {
        if let Some(peer_addr) = self.peer_addr {
            info!("Upgrading connection to KCP with {}", peer_addr);

            // Configure KCP for low-latency (Turbo Mode)
            let config = KcpConfig {
                nodelay: KcpNoDelayConfig {
                    nodelay: true,
                    interval: 10,
                    resend: 2,
                    nc: true,
                },
                wnd_size: (1024, 1024),
                mtu: 1400,
                ..Default::default()
            };

            // Safely clone the socket for KCP to take ownership of.
            let socket = self.clone_socket()?;

            // Connect the KCP stream wrapper.
            self.kcp_stream =
                Some(KcpStream::connect_with_socket(&config, socket, peer_addr).await?);

            info!("KCP upgrade successful.");
            Ok(())
        } else {
            bail!("Handshake not established.")
        }
    }

    /// Sends a binary message over the established KCP stream.
    ///
    /// # Arguments
    ///
    /// * `payload` - The bytes to send.
    pub async fn send_message(&mut self, payload: &[u8]) -> Result<()> {
        if let Some(stream) = &mut self.kcp_stream {
            stream.write_all(payload).await?;
            stream.flush().await?;
            Ok(())
        } else {
            bail!("KCP stream not established");
        }
    }

    /// Reads a message from the KCP stream into the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to write received data into.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The number of bytes read.
    pub async fn receive_message(&mut self, buf: &mut [u8]) -> Result<usize> {
        if let Some(stream) = &mut self.kcp_stream {
            let n = stream.read(buf).await?;
            Ok(n)
        } else {
            bail!("KCP stream not established");
        }
    }

    /// Returns true if the KCP stream is currently active.
    pub fn is_connected(&self) -> bool {
        self.kcp_stream.is_some()
    }

    /// Helper to clone the underlying UDP socket safely.
    ///
    /// `tokio-kcp` requires ownership of a `UdpSocket`, but we only have an `Arc<UdpSocket>`.
    /// This method uses `unsafe` code to duplicate the file descriptor (FD) and wrap it
    /// in a new `UdpSocket` struct.
    ///
    /// # Safety
    ///
    /// This method calls `std::mem::forget` on the temporary `std::net::UdpSocket`
    /// created from the raw FD. This is critical: if the temporary socket were dropped normally,
    /// it would close the FD, killing the original `Arc<UdpSocket>` as well.
    fn clone_socket(&self) -> Result<UdpSocket> {
        #[cfg(unix)]
        {
            use std::os::unix::io::{AsRawFd, FromRawFd};
            let fd = self.client_socket.as_raw_fd();

            // Create a std::net::UdpSocket from the raw fd.
            // must not drop this variable normally, it will close the fd Arc<UdpSocket> relies on.
            let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };

            // try_clone() creates a new file descriptor (dup) that refers to the same socket.
            let new_std_sock = std_sock.try_clone();

            // Forget the original wrapper so the destructor doesn't fire and close the fd.
            std::mem::forget(std_sock);

            let new_std_sock = new_std_sock?;

            // Ensure the new socket is in non-blocking mode for Tokio
            new_std_sock.set_nonblocking(true)?;

            Ok(UdpSocket::from_std(new_std_sock)?)
        }

        #[cfg(not(unix))]
        {
            bail!("Socket cloning is currently only implemented for Unix-like systems.");
        }
    }

    /// Closes the active KCP stream gracefully.
    ///
    /// This method:
    /// 1. Takes the stream out of the struct (setting `self.kcp_stream` to `None`).
    /// 2. Sends a termination signal (shutdown) to the peer.
    /// 3. Drops the stream, closing the *cloned* file descriptor.
    ///
    /// The original `client_socket` remains active.
    #[allow(dead_code)]
    pub async fn close_kcp(&mut self) -> Result<()> {
        if let Some(mut stream) = self.kcp_stream.take() {
            info!("Initiating KCP stream shutdown...");

            // Attempt graceful shutdown. We log errors but don't fail the function
            if let Err(e) = stream.shutdown().await {
                error!("Error during KCP shutdown: {}", e);
            } else {
                info!("KCP stream shutdown completed.");
            }
            // Stream is dropped here, closing the cloned FD.
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::super::web::shared_state::{AppEvent, AppState, Command},
        *,
    };
    use std::os::unix::io::AsRawFd;
    use std::sync::Arc;
    use tokio::sync::{RwLock, broadcast, mpsc};

    /// Helper to create a fresh state for each test.
    fn create_test_state() -> SharedState {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(32);
        let (event_tx, _) = broadcast::channel::<AppEvent>(32);

        // Drain the command channel to prevent it from filling up during tests
        tokio::spawn(async move { while cmd_rx.recv().await.is_some() {} });

        Arc::new(RwLock::new(AppState::new(cmd_tx, event_tx)))
    }

    // Helper to create a dummy message manager with a bound socket
    async fn create_test_manager() -> MessageManager {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let state = create_test_state();
        MessageManager::new(Arc::new(socket), state)
    }

    #[tokio::test]
    async fn test_initialization() {
        let manager = create_test_manager().await;
        assert!(manager.peer_addr.is_none());
        assert!(manager.kcp_stream.is_none());
        assert!(!manager.is_connected());
    }

    #[tokio::test]
    async fn test_upgrade_fails_without_handshake() {
        let mut manager = create_test_manager().await;

        // Should fail because peer_addr is None (handshake not run)
        let result = manager.upgrade_to_kcp().await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Handshake not established."
        );
    }

    #[tokio::test]
    async fn test_send_fails_without_kcp() {
        let mut manager = create_test_manager().await;
        let result = manager.send_message(b"hello").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_receive_fails_without_kcp() {
        let mut manager = create_test_manager().await;
        let mut buf = [0u8; 10];
        let result = manager.receive_message(&mut buf).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_close_kcp_safe_on_none() {
        let mut manager = create_test_manager().await;

        // Should return Ok even if stream is None (idempotent)
        let result = manager.close_kcp().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_socket_cloning_safety() {
        // This test verifies that clone_socket creates a NEW file descriptor
        // and does not close the original one when dropped.

        // 1. Setup socket and manager
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let raw_fd_original = socket.as_raw_fd();
        let socket_arc = Arc::new(socket);
        let manager = MessageManager::new(socket_arc.clone(), create_test_state());

        // 2. Clone the socket
        let cloned_sock = manager.clone_socket().expect("Socket cloning failed");
        let raw_fd_cloned = cloned_sock.as_raw_fd();

        // 3. Verify FDs are different (OS dup() should assign a new number)
        assert_ne!(
            raw_fd_original, raw_fd_cloned,
            "Cloned socket should have a different FD"
        );

        // 4. Drop the cloned socket explicitly
        drop(cloned_sock);

        // 5. Verify the original socket is still alive and working
        // If mem::forget was missed in implementation, this would fail/panic because the FD would be closed
        let test_payload = b"ping";
        // We send to ourselves just to check if the socket write operation fails immediately
        let send_result = socket_arc.send_to(test_payload, "127.0.0.1:8080").await;

        assert!(
            send_result.is_ok(),
            "Original socket should remain valid after cloned socket is dropped"
        );
    }
}
