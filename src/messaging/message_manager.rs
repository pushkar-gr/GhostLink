use super::handshake;
use anyhow::Result;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;

#[derive(Debug)]
pub struct MessageManager {
    client_socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    timeout_secs: u64,
}

impl MessageManager {
    pub async fn new(
        client_socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        timeout_secs: u64,
    ) -> Result<Self> {
        let message_manager = Self {
            client_socket,
            peer_addr,
            timeout_secs,
        };
        handshake::handshake(
            Arc::clone(&message_manager.client_socket),
            message_manager.peer_addr,
            message_manager.timeout_secs,
        )
        .await?;
        Ok(message_manager)
    }
}
