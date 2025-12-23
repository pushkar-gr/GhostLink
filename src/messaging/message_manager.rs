use super::{
    super::web::shared_state::{SharedState, Status},
    handshake,
};
use anyhow::{Result, bail};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;
use tracing::{error, info};

/// Manages the lifecycle of a P2P connection.
///
/// This struct is responsible for:
/// 1. Initiating the connection handshake via the `handshake` module.
/// 2. Managing the active connection state (though currently it just sets up the connection).
/// 3. Handling failures and resetting the application state if the connection drops or fails.
#[derive(Debug)]
pub struct MessageManager {}

impl MessageManager {
    /// Creates a new `MessageManager` and attempts to establish a connection.
    ///
    /// This function blocks asynchronously until the handshake succeeds or fails.
    ///
    /// # Arguments
    ///
    /// * `client_socket` - The local UDP socket.
    /// * `peer_addr` - The target peer's public address.
    /// * `state` - The shared application state.
    /// * `timeout_secs` - Duration to wait for handshake before giving up.
    ///
    /// # Returns
    ///
    /// * `Ok(MessageManager)` - If the handshake is successful.
    /// * `Err` - If the handshake fails or times out. The state will be reset to `Disconnected`.
    pub async fn new(
        client_socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        state: SharedState,
        timeout_secs: u64,
    ) -> Result<Self> {
        info!("Initializing MessageManager for peer {}", peer_addr);

        // Attempt the handshake.
        // The `handshake` function handles the `Punching` -> `Connected` state transitions
        // and UI event broadcasting internally.
        match handshake::handshake(
            client_socket.clone(),
            peer_addr,
            state.clone(),
            timeout_secs,
        )
        .await
        {
            Ok(_) => {
                info!("Handshake successful. MessageManager active.");
            }
            Err(e) => {
                error!("Handshake failed: {}", e);

                state.write().await.set_status(
                    Status::Disconnected,
                    Some(format!("Connection failed: {}", e)),
                    None,
                );
                bail!(e);
            }
        }

        Ok(Self {})
    }
}
