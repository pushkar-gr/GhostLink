use super::super::web::shared_state::{SharedState, Status};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    net::UdpSocket,
    time::{Duration, Instant},
};
use tracing::{debug, info, warn};

/// Represents handshake message being sent or received.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum HandshakeMsg {
    Syn,
    SynAck,
    Bye,
}

/// Performs a UDP hole punching handshake with a remote peer.
///
/// This function attempts to establish a bidirectional connection by sending SYN packets
/// to the peer while also listening for incoming responses. It handles the "Punching"
/// state updates and transitions to "Connected" upon success.
///
/// # Arguments
///
/// * `client_socket` - The local UDP socket to use. Wrapped in `Arc` for thread safety.
/// * `peer_addr` - The public IP address and port of the target peer.
/// * `state` - The shared application state to update status and UI events.
/// * `timeout_secs` - The maximum duration (in seconds) to attempt the handshake.
///
/// # Returns
///
/// * `Ok(())` - If the handshake succeeds (SYN-ACK received).
/// * `Err` - If the operation times out, is rejected, or a socket error occurs.
pub async fn handshake(
    client_socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    state: SharedState,
    timeout_secs: u64,
) -> Result<()> {
    let mut buf = [0u8; 2048];
    let timeout = Duration::from_secs(timeout_secs);
    let start_time = Instant::now();

    // Send SYN packets every 500ms to punch the hole
    let mut send_interval = tokio::time::interval(Duration::from_millis(500));
    send_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Track if client received SYN-ACK
    let mut received_syn_ack = false;
    // Track if client sent SYN-ACK
    let mut sent_syn_ack = false;

    info!("Starting handshake with {}", peer_addr);

    // Update initial state
    {
        let mut guard = state.write().await;
        guard.set_status(
            Status::Punching,
            Some(format!("Starting handshake with {}", peer_addr)),
            Some(timeout_secs),
        );
    }

    loop {
        let elapsed = start_time.elapsed();
        if elapsed > timeout {
            let msg = format!("Handshake timed out with {}", peer_addr);
            // Notify UI of timeout
            state
                .write()
                .await
                .set_status(Status::Punching, Some(msg.clone()), Some(0));
            bail!(msg);
        }

        let secs_left = timeout.as_secs().saturating_sub(elapsed.as_secs());

        tokio::select! {
            // 1. Listen to incoming packets
            result = client_socket.recv_from(&mut buf) => {
                let (len, sender) = result.context("Socket read error")?;

                if sender != peer_addr {
                    debug!("Ignored packet from unknown sender: {}", sender);
                    continue;
                }

                match bincode::deserialize::<HandshakeMsg>(&buf[..len]) {
                    Ok(msg) => match msg {
                        HandshakeMsg::Syn => {
                            info!("Received SYN from {}. Sending SYN-ACK.", sender);

                            // Notify UI
                            state.write().await.set_status(
                                Status::Punching,
                                Some(format!("Received SYN from {}. Sending SYN-ACK.", sender)),
                                Some(secs_left),
                            );

                            let reply = bincode::serialize(&HandshakeMsg::SynAck)?;
                            client_socket.send_to(&reply, peer_addr).await?;

                            sent_syn_ack = true;
                            if received_syn_ack && sent_syn_ack {
                                // Transition to Connected state
                                state.write().await.set_status(
                                    Status::Connected,
                                    Some(format!("Connected to {}", sender)),
                                    None
                                );
                                return Ok(());
                            }

                        }
                        HandshakeMsg::SynAck => {
                            info!("Received SYN-ACK from {}. Sending ACK.", sender);

                            // Transition to Connected state
                            state.write().await.set_status(
                                Status::Punching,
                                Some(format!("Received SYN-ACK from {}. Sending ACK.", sender)),
                                Some(secs_left),
                            );

                            received_syn_ack = true;
                            if received_syn_ack && sent_syn_ack {
                                // Transition to Connected state
                                state.write().await.set_status(
                                    Status::Connected,
                                    Some(format!("Connected to {}", sender)),
                                    None
                                );
                                return Ok(());
                            }
                        }
                        HandshakeMsg::Bye => {
                            warn!("Peer {} rejected connection (received BYE)", sender);
                            state.write().await.set_status(
                                Status::Punching,
                                Some("Connection rejected by peer".into()),
                                Some(secs_left)
                            );
                            bail!("Connection rejected by peer");
                        }
                    },
                    Err(_) => {
                        debug!("Received unparseable packet from {}", sender);
                    }
                }
            }

            // 2. Periodically send SYN to keep NAT mapping open
            _ = send_interval.tick() => {
                let msg = bincode::serialize(&HandshakeMsg::Syn)?;
                client_socket.send_to(&msg, peer_addr).await.context("Failed to send packet")?;

                debug!("Punched hole to {}...", peer_addr);

                // Provide visual feedback to UI
                state.write().await.set_status(
                    Status::Punching,
                    Some(format!("Punching hole to {}...", peer_addr)),
                    Some(secs_left),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::super::web::shared_state::{AppEvent, AppState, Command, Status},
        *,
    };
    use std::{sync::Arc, time::Duration};
    use tokio::{
        net::UdpSocket,
        sync::{RwLock, broadcast, mpsc},
    };

    /// Helper to create a dummy state for testing
    fn create_dummy_state() -> SharedState {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(32);
        let (event_tx, _) = broadcast::channel::<AppEvent>(32);

        // Drain commands to prevent blocking
        tokio::spawn(async move { while cmd_rx.recv().await.is_some() {} });

        Arc::new(RwLock::new(AppState::new(cmd_tx, event_tx)))
    }

    /// Helper to create a socket bound to a random local port
    async fn bind_local() -> Arc<UdpSocket> {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Arc::new(socket)
    }

    #[tokio::test]
    async fn test_handshake_success() {
        let socket_a = bind_local().await;
        let socket_b = bind_local().await;
        let state_a = create_dummy_state();

        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        // Simulate Peer B
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];

            // 1. Send SYN to A so A can fulfill `sent_syn_ack` requirement
            let syn_msg = bincode::serialize(&HandshakeMsg::Syn).unwrap();
            socket_b.send_to(&syn_msg, addr_a).await.unwrap();

            // 2. Respond to A's SYN
            loop {
                let (len, sender) = socket_b.recv_from(&mut buf).await.unwrap();
                if sender == addr_a {
                    if let Ok(msg) = bincode::deserialize::<HandshakeMsg>(&buf[..len]) {
                        if msg == HandshakeMsg::Syn {
                            // Send SYN-ACK back so A can fulfill `received_syn_ack`
                            let reply = bincode::serialize(&HandshakeMsg::SynAck).unwrap();
                            socket_b.send_to(&reply, addr_a).await.unwrap();
                            break;
                        }
                    }
                }
            }
        });

        let result = handshake(socket_a, addr_b, state_a.clone(), 5).await;
        assert!(result.is_ok());

        let locked = state_a.read().await;
        assert_eq!(locked.status, Status::Connected);
    }

    #[tokio::test]
    async fn test_handshake_timeout() {
        let socket_a = bind_local().await;
        let socket_b = bind_local().await;
        let state_a = create_dummy_state();
        let addr_b = socket_b.local_addr().unwrap();

        let result = handshake(socket_a, addr_b, state_a, 1).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn test_handshake_ignores_wrong_sender() {
        let socket_a = bind_local().await;
        let socket_b = bind_local().await; // Real Peer
        let socket_c = bind_local().await; // Attacker
        let state_a = create_dummy_state();

        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        tokio::spawn(async move {
            // 1. Attacker strikes first
            tokio::time::sleep(Duration::from_millis(200)).await;
            socket_c.send_to(b"FAKE_PACKET", addr_a).await.unwrap();

            // 2. Real peer replies later
            tokio::time::sleep(Duration::from_millis(1000)).await;

            // Peer sends SYN
            let syn = bincode::serialize(&HandshakeMsg::Syn).unwrap();
            socket_b.send_to(&syn, addr_a).await.unwrap();

            // Peer sends SYN-ACK
            let reply = bincode::serialize(&HandshakeMsg::SynAck).unwrap();
            socket_b.send_to(&reply, addr_a).await.unwrap();
        });

        let result = handshake(socket_a, addr_b, state_a, 5).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handshake_rejects_bye_packet() {
        let socket_a = bind_local().await;
        let socket_b = bind_local().await;
        let state_a = create_dummy_state();

        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let bye = bincode::serialize(&HandshakeMsg::Bye).unwrap();
            socket_b.send_to(&bye, addr_a).await.unwrap();
        });

        let result = handshake(socket_a, addr_b, state_a, 2).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Connection rejected by peer"
        );
    }

    #[tokio::test]
    async fn test_handshake_handles_simultaneous_syn() {
        let socket_a = bind_local().await;
        let socket_b = bind_local().await;
        let state_a = create_dummy_state();
        let _state_b = create_dummy_state();

        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        // Peer B logic - simulates another peer also initiating handshake
        let socket_b_clone = socket_b.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];

            // 1. Send SYN to A proactively
            let syn = bincode::serialize(&HandshakeMsg::Syn).unwrap();
            socket_b_clone.send_to(&syn, addr_a).await.unwrap();

            // 2. Receive SYN from A and Reply
            loop {
                let (len, sender) = socket_b_clone.recv_from(&mut buf).await.unwrap();
                if sender == addr_a {
                    if let Ok(HandshakeMsg::Syn) = bincode::deserialize(&buf[..len]) {
                        // Send SYN-ACK back
                        let reply = bincode::serialize(&HandshakeMsg::SynAck).unwrap();
                        socket_b_clone.send_to(&reply, addr_a).await.unwrap();
                        break;
                    }
                }
            }
        });

        let result = handshake(socket_a, addr_b, state_a.clone(), 5).await;
        assert!(result.is_ok());
        assert_eq!(state_a.read().await.status, Status::Connected);
    }

    /// Test that both peers complete handshake when initiating simultaneously
    /// Verifies the fix for the issue where user B would mark as connected
    /// and ignore further SYN packets from user A
    #[tokio::test]
    async fn test_both_peers_complete_handshake_when_initiating_simultaneously() {
        let socket_a = bind_local().await;
        let socket_b = bind_local().await;
        let state_a = create_dummy_state();
        let state_b = create_dummy_state();

        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        // Both peers start handshake simultaneously
        let socket_a_clone = socket_a.clone();
        let state_a_clone = state_a.clone();
        let handle_a =
            tokio::spawn(async move { handshake(socket_a_clone, addr_b, state_a_clone, 5).await });

        let socket_b_clone = socket_b.clone();
        let state_b_clone = state_b.clone();
        let handle_b =
            tokio::spawn(async move { handshake(socket_b_clone, addr_a, state_b_clone, 5).await });

        // Both should complete successfully
        let result_a = handle_a.await.unwrap();
        let result_b = handle_b.await.unwrap();

        assert!(result_a.is_ok(), "Peer A should complete handshake");
        assert!(result_b.is_ok(), "Peer B should complete handshake");

        assert_eq!(state_a.read().await.status, Status::Connected);
        assert_eq!(state_b.read().await.status, Status::Connected);
    }
}
