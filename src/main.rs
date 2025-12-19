mod config;
mod net;

use crate::config::Config;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    info!("GhostLink v1.0 Starting...");

    let config = Config::load();
    info!("Config loaded. Target STUN: {}", config.stun_server);

    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    let socket = Arc::new(socket);

    let local_port = socket.local_addr()?.port();
    info!("UDP Socket bound locally to port: {}", local_port);

    match net::resolve_public_ip(&socket, &config.stun_server).await {
        Ok(public_addr) => {
            info!("STUN Success! Your Public ID is: {}", public_addr);
            info!("Share this address with your peer to connect.");
        }
        Err(e) => {
            error!("STUN Failed: {:?}", e);
            warn!("You may not be reachable from the internet.");
        }
    }
    Ok(())
}
