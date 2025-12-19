mod config;
mod net;
mod web;

use crate::{
    config::Config,
    web::shared_state::Status,
    web::{shared_state::AppState, web_server},
};
use std::sync::Arc;
use tokio::{net::UdpSocket, sync::RwLock};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    info!("GhostLink v1.0 Starting...");

    let config = Config::load();
    info!("Config loaded. Target STUN: {}", config.stun_server);

    let shared_state = Arc::new(RwLock::new(AppState::new(None, Status::Disconnected)));

    let state_clone = Arc::clone(&shared_state);
    let web = tokio::spawn(async move {
        if let Err(e) = web_server::serve(state_clone, config.web_port).await {
            error!("Web server crahsed: {:?}", e);
        }
    });

    let socket = UdpSocket::bind("0.0.0.0:0").await?;

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

    web.await?;

    Ok(())
}
