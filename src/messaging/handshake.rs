use super::super::web::shared_state::{AppEvent, AppState, Status};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    net::UdpSocket,
    sync::RwLock,
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
/// This function tires to establish a bidirectional connection by sending SYN packets
/// to the peer while also listening for incoming response from that peer.
///
/// Uses tokio::select! to handle send/receive loop without blocking.
///
/// * `client_socket` - The local UDP socket to use for the handshake. Wrapped in `Arc` for thread safety.
/// * `peer_addr` - The public IP address and port of the peer to connect to.
/// * `timeout_secs` - The maximum duration (in seconds) to attempt the handshake before giving up.
///
/// # Returns
///
/// * `Ok(())` - If a packet (any payload) is received from `peer_addr` within the timeout.
/// * `Err` - If the operation times out or a socket error occurs.
pub async fn handshake(
    client_socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    state: Arc<RwLock<AppState>>,
    timeout_secs: u64,
) -> Result<()> {
    let mut buf = [0u8; 2048];
    let timeout = Duration::from_secs(timeout_secs);
    let start_time = Instant::now();
    let mut send_interval = tokio::time::interval(Duration::from_millis(500));

    let event_tx = { state.read().await.event_tx.clone() };

    info!("Starting handshake with {}", peer_addr);

    // Prevent a burst of ticks when the task is delayed.
    send_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        // Check timeout at every iteration.
        if start_time.elapsed() > timeout {
            let _ = event_tx.send(AppEvent::Punching {
                timeout: Some(0),
                message: Some(format!(
                    "{}: Handshake timed out with {}",
                    chrono::Local::now(),
                    peer_addr
                )),
            });
            bail!("Handshake timed out with {}", peer_addr);
        }

        let secs_left = timeout.as_secs() - start_time.elapsed().as_secs();

        tokio::select! {
            // 1. Listen to incoming packets.
            result = client_socket.recv_from(&mut buf) => {
                let (len, sender) = result.context("Socket read error")?;

                // Ignore packets from unknown senders
                if sender == peer_addr {
                    match bincode::deserialize::<HandshakeMsg>(&buf[..len]) {
                        Ok(msg) => match msg {
                            HandshakeMsg::Syn => {
                                // Peer is punching us -> Reply "SynAck"
                                info!("Received SYN from {}. Sending SYN-ACK.", sender);

                                let _ = event_tx.send(AppEvent::Punching {
                                    timeout: Some(secs_left),
                                    message: Some(format!("Received SYN from {}. Sending SYN-ACK.", sender)),
                                });

                                let reply = bincode::serialize(&HandshakeMsg::SynAck)?;
                                client_socket.send_to(&reply, peer_addr).await?;
                            }
                            HandshakeMsg::SynAck => {
                                info!("Received SYN-ACK from {}! Connection Established.", sender);

                                let _ = event_tx.send(AppEvent::Punching {
                                    timeout: Some(secs_left),
                                    message: Some(format!("Received SYN-ACK from {}! Connection Established.", sender)),
                                });

                                state.write().await.status = Status::Connected;
                                return Ok(());
                            }
                            HandshakeMsg::Bye => {
                                let _ = event_tx.send(AppEvent::Punching {
                                    timeout: Some(secs_left),
                                    message: Some("Connection rejected by peer".to_string()),
                                });
                                warn!("Peer {} rejected connection (received BYE)", sender);
                                bail!("Connection rejected by peer");
                            }
                        },
                        Err(_) => {
                            debug!("Received unparseable packet from {}", sender);
                        }
                    }
                } else {
                    debug!("Ignored packet from unknown sender: {}", sender);
                }
            }

            // 2. Periodically send SYN to keep NAT mapping open
            _ = send_interval.tick() => {
                let msg = bincode::serialize(&HandshakeMsg::Syn)?;
                client_socket.send_to(&msg, peer_addr).await.context("Failed to send packet")?;

                debug!("Punched hole to {}...", peer_addr);
                let _ = event_tx.send(AppEvent::Punching {
                    timeout: Some(secs_left),
                    message: Some(format!("Punched hole to {}...", peer_addr)),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::web::shared_state::{AppState, Command, Status};
    use super::*;
    use std::{sync::Arc, time::Duration};
    use tokio::{
        net::UdpSocket,
        sync::{RwLock, broadcast, mpsc},
    };

    /// Helper to create a dummy state for testing
    fn create_dummy_state() -> Arc<RwLock<AppState>> {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(32);
        let (event_tx, _) = broadcast::channel::<AppEvent>(32);
        // listen to cmd_rx and do nothing
        tokio::spawn(async move { while let Some(_cmd) = cmd_rx.recv().await {} });

        Arc::new(RwLock::new(AppState::new(
            None,
            Status::Disconnected,
            None,
            cmd_tx,
            event_tx,
        )))
    }

    /// Helper to create a socket bound to a random local port
    async fn bind_local() -> Arc<UdpSocket> {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Arc::new(socket)
    }

    /// Verifies that the handshake succeeds when the peer replies.
    /// It simulates a peer (B) receiving SYN and then sending "SynAck".
    /// We expect `handshake` to return `Ok`.
    #[tokio::test]
    async fn test_handshake_success() {
        let socket_a = bind_local().await;
        let socket_b = bind_local().await;
        let state_a = create_dummy_state();

        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];

            //Wait for peer_1 to send SYN
            let (len, _) = socket_b.recv_from(&mut buf).await.unwrap();
            let msg: HandshakeMsg = bincode::deserialize(&buf[..len]).unwrap();
            assert_eq!(msg, HandshakeMsg::Syn);

            //Send SYN-ACK back
            let reply = bincode::serialize(&HandshakeMsg::SynAck).unwrap();
            socket_b.send_to(&reply, addr_a).await.unwrap();
        });

        let result = handshake(socket_a, addr_b, state_a.clone(), 5).await;
        assert!(result.is_ok());

        let locked = state_a.read().await;
        // Verify logs contain success message
        assert_eq!(locked.status, Status::Connected);
    }

    /// Verifies that the function gives up if the peer is silent.
    #[tokio::test]
    async fn test_handshake_timeout() {
        let socket_a = bind_local().await;
        let socket_b = bind_local().await;
        let state_a = create_dummy_state();
        let addr_b = socket_b.local_addr().unwrap();

        let result = handshake(socket_a, addr_b, state_a, 2).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }

    /// Verifies that we ignore packets from random people.
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

            // 2. Real peer replies later (simulated SynAck)
            tokio::time::sleep(Duration::from_millis(1000)).await;
            let reply = bincode::serialize(&HandshakeMsg::SynAck).unwrap();
            socket_b.send_to(&reply, addr_a).await.unwrap();
        });

        let result = handshake(socket_a, addr_b, state_a, 5).await;
        assert!(result.is_ok());
    }

    /// Verifies that we respect a peer saying "BYE".
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

    /// Verifies that multiple SYN packets are handled correctly without breaking the handshake.
    #[tokio::test]
    async fn test_handshake_handles_multiple_syn() {
        let socket_a = bind_local().await;
        let socket_b = bind_local().await;
        let state_a = create_dummy_state();

        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];

            // Receive first SYN
            let (len, _) = socket_b.recv_from(&mut buf).await.unwrap();
            let msg: HandshakeMsg = bincode::deserialize(&buf[..len]).unwrap();
            assert_eq!(msg, HandshakeMsg::Syn);

            // Send multiple SYN-ACK responses (simulating retries)
            for _ in 0..3 {
                let reply = bincode::serialize(&HandshakeMsg::SynAck).unwrap();
                socket_b.send_to(&reply, addr_a).await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        let result = handshake(socket_a, addr_b, state_a.clone(), 5).await;
        assert!(result.is_ok());
        assert_eq!(state_a.read().await.status, Status::Connected);
    }

    /// Verifies that handshake can handle receiving SYN from peer (simultaneous connection).
    #[tokio::test]
    async fn test_handshake_simultaneous_syn() {
        let socket_a = bind_local().await;
        let socket_b = bind_local().await;
        let state_a = create_dummy_state();

        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        // Peer B also tries to handshake with A
        let socket_b_clone = socket_b.clone();
        tokio::spawn(async move {
            // Wait for A's SYN
            let mut buf = [0u8; 1024];
            let (len, sender) = socket_b_clone.recv_from(&mut buf).await.unwrap();

            if sender == addr_a {
                if let Ok(HandshakeMsg::Syn) = bincode::deserialize(&buf[..len]) {
                    // Respond with SYN-ACK
                    let reply = bincode::serialize(&HandshakeMsg::SynAck).unwrap();
                    socket_b_clone.send_to(&reply, addr_a).await.unwrap();
                }
            }
        });

        let result = handshake(socket_a, addr_b, state_a.clone(), 5).await;
        assert!(result.is_ok());
        assert_eq!(state_a.read().await.status, Status::Connected);
    }

    /// Verifies that unparseable packets don't crash the handshake process.
    #[tokio::test]
    async fn test_handshake_resilient_to_malformed_packets() {
        let socket_a = bind_local().await;
        let socket_b = bind_local().await;
        let state_a = create_dummy_state();

        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;

            // Send garbage data
            socket_b
                .send_to(b"GARBAGE_DATA_12345", addr_a)
                .await
                .unwrap();

            tokio::time::sleep(Duration::from_millis(500)).await;

            // Then send proper SYN-ACK
            let reply = bincode::serialize(&HandshakeMsg::SynAck).unwrap();
            socket_b.send_to(&reply, addr_a).await.unwrap();
        });

        let result = handshake(socket_a, addr_b, state_a.clone(), 5).await;
        assert!(result.is_ok());
        assert_eq!(state_a.read().await.status, Status::Connected);
    }
}
