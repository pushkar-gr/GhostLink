mod config;
mod messaging;
mod net;
mod web;

use crate::{
    config::Config,
    messaging::message_manager::MessageManager,
    web::{
        shared_state::{AppState, Command, SharedState, Status},
        web_server,
    },
};
use anyhow::Result;
use std::sync::Arc;
use tokio::{
    net::UdpSocket,
    sync::{RwLock, mpsc},
};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    info!("GhostLink v1.0 Starting...");

    let config = Config::load();
    info!("Config loaded...");

    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(32);

    let shared_state = Arc::new(RwLock::new(AppState::new(
        None,
        Status::Disconnected,
        None,
        cmd_tx,
    )));

    let state_clone = Arc::clone(&shared_state);
    let web = tokio::spawn(async move {
        if let Err(e) = web_server::serve(state_clone, config.web_port).await {
            error!("Web server crashed: {:?}", e);
        }
    });

    start_controller(&config, &shared_state, cmd_rx).await?;

    web.await?;

    Ok(())
}

async fn start_controller(
    config: &Config,
    shared_state: &SharedState,
    mut cmd_rx: mpsc::Receiver<Command>,
) -> Result<()> {
    // 1. Bind the UDP Socket
    let socket = UdpSocket::bind(("0.0.0.0", config.client_port)).await?;
    let socket = Arc::new(socket);

    let local_port = socket.local_addr()?.port();
    info!("UDP Socket bound locally to port: {}", local_port);

    // 2. Resolve Public IP
    match net::resolve_public_ip(&socket, &config.stun_server).await {
        Ok(public_addr) => {
            info!("STUN Success! Your Public ID is: {}", public_addr);
            info!("Share this address with your peer to connect.");
            let mut locked_state = shared_state.write().await;
            locked_state.public_ip = Some(public_addr);
        }
        Err(e) => {
            error!("STUN Failed: {:?}", e);
            warn!("You may not be reachable from the internet.");
        }
    };

    // 3. Command Loop (Wait for user to click "Connect" in UI)
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            Command::ConnectPeer => {
                info!("Command received: ConnectPeer");
                let peer_addr = {
                    let locked_state = shared_state.read().await;
                    locked_state.peer_ip
                };

                if let Some(peer_addr) = peer_addr {
                    info!("Initiating handshake with: {}", peer_addr);

                    // establish messaging connection between peer and client
                    if let Err(e) = MessageManager::new(
                        Arc::clone(&socket),
                        peer_addr,
                        Arc::clone(shared_state),
                        config.timeout_secs,
                    )
                    .await
                    {
                        error!("Connection failed: {:?}", e);
                    } else {
                        info!("Handshake complete. MessageManager ready.");
                    }
                } else {
                    warn!("Connect command received but no peer IP set.");
                }
            }
        }
    }

    Ok(())
}
