mod config;
mod messaging;
mod net;
mod web;

use crate::{
    config::Config,
    messaging::message_manager::MessageManager,
    web::{
        shared_state::{AppEvent, AppState, Command, SharedState},
        web_server,
    },
};
use anyhow::Result;
use std::sync::Arc;
use tokio::{
    net::UdpSocket,
    sync::{RwLock, broadcast, mpsc},
};
use tracing::{debug, error, info, warn};

/// The main entry point for the GhostLink application.
///
/// It initializes the application components:
/// 1. Loads configuration.
/// 2. Sets up communication channels (Command & Event loops).
/// 3. Initializes the shared application state.
/// 4. Starts the Web Server (UI).
/// 5. Starts the Controller (Networking & Logic).
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    info!("GhostLink v1.0 Starting...");

    // Load configuration
    let config = Config::load();
    info!("Config loaded successfully.");

    // Create channels for communication between Web Server and Controller
    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(32);
    let (event_tx, _event_rx) = broadcast::channel::<AppEvent>(32);

    // Initialize Shared State
    // Note: We use the new constructor which automatically defaults internal fields.
    let shared_state = Arc::new(RwLock::new(AppState::new(cmd_tx, event_tx)));

    // Spawn Web Server
    let state_clone = Arc::clone(&shared_state);
    let web_server_handle = tokio::spawn(async move {
        let port = config.web_port;
        if let Err(e) = web_server::serve(state_clone, port).await {
            error!("Web server crashed: {:?}", e);
        }
    });

    // Start the Controller (Main Logic)
    // We await this as it runs the main event loop
    if let Err(e) = start_controller(&config, &shared_state, cmd_rx).await {
        error!("Controller encountered a critical error: {:?}", e);
    }

    // Wait for web server (optional, usually controller keeps app alive)
    let _ = web_server_handle.await;

    Ok(())
}

/// Starts the main controller logic.
///
/// This function:
/// 1. Binds the UDP socket.
/// 2. Performs STUN resolution to find the public IP.
/// 3. Enters a command loop to handle user actions (like "Connect").
async fn start_controller(
    config: &Config,
    shared_state: &SharedState,
    mut cmd_rx: mpsc::Receiver<Command>,
) -> Result<()> {
    // 1. Bind the UDP Socket
    // We bind to 0.0.0.0 to listen on all interfaces.
    let socket = UdpSocket::bind(("0.0.0.0", config.client_port)).await?;
    let socket = Arc::new(socket);

    let local_port = socket.local_addr()?.port();
    info!("UDP Socket bound locally to port: {}", local_port);

    // 2. Resolve Public IP via STUN
    // Note: We pass a reference to the socket. net::resolve_public_ip now expects &UdpSocket.
    match net::resolve_public_ip(&socket, &config.stun_server).await {
        Ok(public_addr) => {
            info!("STUN Success! Your Public IP is: {}", public_addr);
            info!("Share this address with your peer to connect.");

            // Update state safely using the setter.
            // This triggers an event update so the UI displays the IP immediately.
            shared_state.write().await.set_public_ip(
                public_addr,
                Some("STUN Resolution Successful".into()),
                None,
            );
        }
        Err(e) => {
            error!("STUN Resolution Failed: {:?}", e);
            warn!("You may not be reachable from the internet.");
        }
    };

    // 3. Command Loop (Wait for signals from the Web UI)
    info!("Waiting for commands...");
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            Command::ConnectPeer => {
                debug!("Command received: ConnectPeer");

                // Read the target peer IP from state
                let peer_ip_opt = shared_state.read().await.peer_ip;

                if let Some(peer_addr) = peer_ip_opt {
                    debug!("Initiating connection to peer: {}", peer_addr);

                    // Create a new MessageManager to handle the connection lifecycle.
                    // This blocks asynchronously until the handshake completes or fails.
                    // If it fails, MessageManager handles resetting the state to Disconnected.
                    if let Err(e) = MessageManager::new(
                        Arc::clone(&socket),
                        peer_addr,
                        Arc::clone(shared_state),
                        config.timeout_secs,
                    )
                    .await
                    {
                        error!("Connection attempt failed: {:?}", e);
                    } else {
                        debug!("Connection established successfully. MessageManager active.");
                    }
                } else {
                    warn!("Connect command received but no peer IP is set in state.");
                }
            }
        }
    }

    Ok(())
}
