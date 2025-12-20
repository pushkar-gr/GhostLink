mod config;
mod messaging;
mod net;
mod web;

use crate::{
    config::Config,
    messaging::message_manager::MessageManager,
    web::shared_state::Status,
    web::{shared_state::AppState, web_server},
};
use std::sync::Arc;
use tokio::{net::UdpSocket, sync::RwLock};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    info!("GhostLink v1.0 Starting...");

    let config = Config::load();
    info!("Config loaded. Target STUN: {}", config.stun_server);

    let shared_state = Arc::new(RwLock::new(AppState::new(None, Status::Disconnected, None)));

    let state_clone = Arc::clone(&shared_state);
    let web = tokio::spawn(async move {
        if let Err(e) = web_server::serve(state_clone, config.web_port).await {
            error!("Web server crashed: {:?}", e);
        }
    });

    let socket = UdpSocket::bind(("0.0.0.0", config.client_port)).await?;

    let socket = Arc::new(socket);

    let local_port = socket.local_addr()?.port();
    info!("UDP Socket bound locally to port: {}", local_port);

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

    // wait for user to click connect
    let peer_addr = {
        let locked_state = shared_state.read().await;
        locked_state.peer_ip
    };

    if let Some(peer_addr) = peer_addr {
        //passing shared_state to update ui
        MessageManager::new(
            Arc::clone(&socket),
            peer_addr,
            Arc::clone(&shared_state),
            config.timeout_secs,
        )
        .await?;
    }

    web.await?;

    Ok(())
}
