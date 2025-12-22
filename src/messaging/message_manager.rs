use super::{
    super::web::shared_state::{AppEvent, AppState, Status},
    handshake,
};
use anyhow::{Result, bail};
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::UdpSocket, sync::RwLock};
use tracing::info;

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
        state: Arc<RwLock<AppState>>,
        timeout_secs: u64,
    ) -> Result<Self> {
        let message_manager = Self {
            client_socket,
            peer_addr,
            timeout_secs,
        };
        let event_tx = {
            let mut state = state.write().await;
            state.status = Status::Punching;
            state.event_tx.clone()
        };
        let _ = event_tx.send(AppEvent::Punching {
            timeout: None,
            message: None,
        });

        match handshake::handshake(
            Arc::clone(&message_manager.client_socket),
            message_manager.peer_addr,
            Arc::clone(&state),
            message_manager.timeout_secs,
        )
        .await
        {
            Ok(_) => {
                info!("Connected to peer");
                let event_tx = {
                    let mut state = state.write().await;
                    state.status = Status::Connected;
                    state.event_tx.clone()
                };
                let _ = event_tx.send(AppEvent::Connected { message: None });
            }
            Err(e) => {
                info!("Unable to connect peer");
                let event_tx = {
                    let mut state = state.write().await;
                    state.status = Status::Disconnected;
                    state.event_tx.clone()
                };
                let _ = event_tx.send(AppEvent::Disconnected {
                    public_ip: state.read().await.public_ip,
                });
                bail!(e);
            }
        }

        Ok(message_manager)
    }
}
