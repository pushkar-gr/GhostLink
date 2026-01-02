mod config;
mod messaging;
mod net;
mod web;

use crate::{
    config::Config,
    messaging::message_manager::{MessageManager, StreamMessage},
    web::shared_state::{AppState, Command, Status},
};
use anyhow::Result;
use std::sync::Arc;
use tokio::{
    net::UdpSocket,
    sync::{RwLock, broadcast, mpsc},
    time::Duration,
};
use tracing::{debug, error, info, warn};

/// Application entry point.
///
/// Initializes:
/// 1. Logging system
/// 2. Configuration
/// 3. Communication channels
/// 4. Application state
/// 5. Web server
/// 6. Network controller (MessageManager)
#[tokio::main]
async fn main() -> Result<()> {
    // 1. Initialize logging
    tracing_subscriber::fmt::init();
    info!("Starting GhostLink v1.1 (Secure)");

    // 2. Load configuration
    let config = Config::load();
    debug!("Configuration loaded: {:?}", config);

    // 3. Bind UDP socket
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", config.client_port)).await?;
    let socket = Arc::new(socket);
    let local_port = socket.local_addr()?.port();
    info!("Listening on UDP port {}", local_port);

    // 4. Initialize Shared State
    let (cmd_tx, mut cmd_rx) = mpsc::channel(32);
    let (event_tx, _) = broadcast::channel(32);
    let state = Arc::new(RwLock::new(AppState::new(cmd_tx.clone(), event_tx)));

    // Resolve Initial Local IP
    if let Ok(local_addr) = net::get_local_ip(local_port).await {
        state.write().await.set_local_ip(local_addr, None, None);
        info!("Local IP resolved: {}", local_addr);
    }

    // Resolve Public IP & Detect NAT Type
    info!("Resolving Public IP and NAT Type...");
    match net::resolve_public_ip(&socket, &config.stun_server).await {
        Ok(public_addr) => {
            info!("Public IP resolved via STUN: {}", public_addr);

            state
                .write()
                .await
                .set_public_ip(public_addr, Some("Public IP resolved".into()), None);

            let nat_type = net::get_nat_type(&socket, &config.stun_verifier, public_addr).await;

            state
                .write()
                .await
                .set_nat_type(nat_type, Some("NAT type detected".into()), None);

            info!("NAT type: {:?}", nat_type);
        }
        Err(e) => {
            error!("STUN resolution failed: {:?}", e);
            warn!("Cannot accept incoming connections without public IP");
        }
    };

    // 5. Start Web Server (Background Task)
    let web_state = state.clone();
    let web_port = config.web_port;
    tokio::spawn(async move {
        if let Err(e) = web::start_web_server(web_state, web_port).await {
            error!("Web server crashed: {}", e);
        }
    });

    // 6. Spawn signal handler for graceful shutdown
    let cmd_tx_clone = cmd_tx.clone();
    let disconnect_timeout = config.disconnect_timeout_ms;
    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                info!("Received Ctrl+C signal, initiating graceful shutdown");
                if let Err(e) = cmd_tx_clone.send(Command::Disconnect).await {
                    warn!("Failed to send disconnect command on shutdown: {}", e);
                }
                tokio::time::sleep(Duration::from_millis(disconnect_timeout)).await;
                std::process::exit(0);
            }
            Err(e) => {
                error!("Failed to listen for Ctrl+C: {}", e);
            }
        }
    });

    // 7. Initialize Message Manager
    let mut manager = MessageManager::new(socket.clone(), state.clone());

    // 8. Setup NAT Keep-Alive
    let mut keep_alive_interval =
        tokio::time::interval(Duration::from_secs(config.punch_hole_secs));
    keep_alive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut receive_buf = [0u8; 4096];

    info!("System Ready. Press Ctrl+C to exit.");

    // 9. Main Event Loop
    loop {
        tokio::select! {
            // A. Handle Commands from Web UI
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    Command::ConnectPeer => {
                        let target_peer = {
                            state.read().await.peer_ip
                        };

                        if let Some(peer_addr) = target_peer {
                            state.write().await.set_status(
                                Status::Punching,
                                Some(format!("Initiating handshake with {}...", peer_addr)),
                                Some(config.handshake_timeout_secs),
                            );

                            if let Err(e) = manager.handshake(
                                peer_addr,
                                config.handshake_timeout_secs,
                                config.encryption_mode
                            ).await {
                                error!("Handshake failed: {}", e);
                            } else if let Err(e) = manager.upgrade_to_kcp().await {
                                error!("Failed to upgrade to KCP: {}", e);
                                state.write().await.set_status(
                                    Status::Disconnected,
                                    Some(format!("KCP Upgrade failed: {}", e)),
                                    None
                                );
                            } else {
                                state.write().await.set_status(
                                    Status::Connected,
                                    Some("Connected securely via KCP".into()),
                                    None
                                );
                            }
                        } else {
                            warn!("ConnectPeer command received without peer IP set");
                        }
                    }
                    Command::SendMessage(text) => {
                        if manager.is_connected() {
                            if let Err(e) = manager.send_text(text.clone()).await {
                                error!("Failed to send message: {}", e);
                            } else {
                                state.read().await.add_message(text, true);
                            }
                        } else {
                            warn!("Cannot send message: not connected");
                        }
                    }
                    Command::Disconnect => {
                        if let Err(e) = manager.disconnect().await {
                            error!("Error during disconnect: {}", e);
                        }
                    }
                }
            }

            // B. Handle Incoming Messages (KCP)
            result = manager.receive_message(&mut receive_buf), if manager.is_connected() => {
                match result {
                    Ok(n) => {
                         match bincode::deserialize::<StreamMessage>(&receive_buf[..n]) {
                            Ok(msg) => {
                                match msg {
                                    StreamMessage::Text(content) => {
                                        debug!("Received message: {} bytes", content.len());
                                        state.read().await.add_message(content, false);
                                    }
                                    StreamMessage::Bye => {
                                        info!("Peer requested disconnect");
                                        let _ = manager.disconnect_on_bye_received().await;
                                    }
                                }
                            }
                            Err(e) => warn!("Failed to deserialize packet: {}", e),
                         }
                    }
                    Err(e) => {
                        error!("KCP receive error: {}", e);
                    }
                }
            }

            // C. Handle NAT Keep-Alive
            _ = keep_alive_interval.tick() => {
                let status = state.read().await.status;

                if status == Status::Disconnected {
                    debug!("Sending NAT keep-alive to STUN server");
                    match net::resolve_public_ip(&socket, &config.stun_server).await {
                        Ok(addr) => {
                            let mut guard = state.write().await;
                            if guard.public_ip != Some(addr) {
                                info!("Public IP changed from {:?} to {}", guard.public_ip, addr);
                                guard.set_public_ip(addr, Some("Public IP updated".into()), None);
                            }
                        }
                        Err(e) => {
                            debug!("Keep-alive STUN check failed: {}", e);
                        }
                    }
                }
            }
        }
    }
}
