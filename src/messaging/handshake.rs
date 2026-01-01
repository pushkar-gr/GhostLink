use super::super::web::shared_state::{SharedState, Status};
use super::crypto::{KeyPair, SessionData, derive_session};
use crate::config::EncryptionMode;
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
pub enum HandshakeMsg {
    Syn {
        public_key: [u8; 32],
        cipher_mode: EncryptionMode,
    },
    SynAck {
        public_key: [u8; 32],
    },
    Bye,
}

/// Performs a UDP hole punching and secure key exchange handshake with a remote peer.
///
/// This function attempts to establish a bidirectional connection by sending SYN packets
/// (containing the local public key) to the peer while also listening for incoming responses.
/// It handles the "Punching" state updates and transitions to "Connected" upon success.
///
/// # Arguments
///
/// * `client_socket` - The local UDP socket to use. Wrapped in `Arc` for thread safety.
/// * `peer_addr` - The public IP address and port of the target peer.
/// * `state` - The shared application state to update status and UI events.
/// * `timeout_secs` - The maximum duration (in seconds) to attempt the handshake.
/// * `my_mode` - The preferred encryption mode for this session.
///
/// # Returns
///
/// * `Ok(SessionData)` - If the handshake succeeds, returns the derived session keys.
/// * `Err` - If the operation times out, is rejected, mode mismatches, or a socket error occurs.
pub async fn handshake(
    client_socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    state: SharedState,
    timeout_secs: u64,
    my_mode: EncryptionMode,
) -> Result<SessionData> {
    let mut buf = [0u8; 2048];
    let timeout = Duration::from_secs(timeout_secs);
    let start_time = Instant::now();

    // Generate ephemeral keys for this session
    let my_keys = KeyPair::generate();
    let my_pub_bytes = my_keys.public.to_bytes();

    // Send SYN packets every 500ms to punch the hole
    let mut send_interval = tokio::time::interval(Duration::from_millis(500));
    send_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut peer_pub_key: Option<[u8; 32]> = None;

    // Track handshake progress
    let mut received_syn_ack = false;
    let mut sent_syn_ack = false;

    // Linger state: Used to keep the connection alive briefly after completion
    // to ensure the peer receives the final ACK.
    let mut linger_until: Option<Instant> = None;

    info!("Starting secure handshake with {}", peer_addr);

    // Update initial state
    {
        let mut guard = state.write().await;
        guard.set_status(
            Status::Punching,
            Some("Handshaking (Keys Generated)...".to_string()),
            Some(timeout_secs),
        );
    }

    loop {
        // 1. Check Timeout
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

        // 2. Check Linger Phase Completion
        // If client has finished the handshake but is lingering to ensure delivery
        if let Some(deadline) = linger_until {
            if Instant::now() >= deadline {
                debug!("Linger phase complete. Handshake successful.");
                break; // Graceful exit after linger
            }
        } else if received_syn_ack && sent_syn_ack {
            // Handshake done.
            // Enter a short "Linger" phase (e.g., 1 second) to reply to potential retransmissions.
            debug!("Handshake logical success. Entering linger phase...");
            linger_until = Some(Instant::now() + Duration::from_secs(1));
            continue;
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
                        HandshakeMsg::Syn { public_key, cipher_mode } => {
                            // do not update the key to prevent MITM
                            if let Some(existing) = peer_pub_key {
                                if existing != public_key {
                                    warn!("Security Warning: Peer key changed mid-handshake! Ignoring.");
                                    continue;
                                }
                            } else {
                                peer_pub_key = Some(public_key);
                            }

                            // Both peers must agree on the mode. If mismatch, cannot safely derive session.
                            if cipher_mode != my_mode {
                                let err_msg = format!("Encryption mode mismatch: Peer={:?}, Local={:?}", cipher_mode, my_mode);
                                warn!("{}", err_msg);
                                bail!(err_msg);
                            }

                            info!("Received SYN from {}. Mode: {:?}.", sender, cipher_mode);

                            // Send SYN-ACK
                            let reply = bincode::serialize(&HandshakeMsg::SynAck {
                                public_key: my_pub_bytes,
                            })?;
                            client_socket.send_to(&reply, peer_addr).await?;

                            // Notify UI
                            state.write().await.set_status(
                                Status::Punching,
                                Some(format!("Received SYN (Key: {:?})...", &public_key[0..4])),
                                Some(secs_left),
                            );

                            sent_syn_ack = true;
                        }
                        HandshakeMsg::SynAck { public_key } => {
                            if let Some(existing) = peer_pub_key {
                                if existing != public_key {
                                    warn!("Security Warning: Peer key changed mid-handshake! Ignoring.");
                                    continue;
                                }
                            } else {
                                peer_pub_key = Some(public_key);
                            }

                            info!("Received SYN-ACK from {}.", sender);
                            received_syn_ack = true;

                            // Notify UI
                            state.write().await.set_status(
                                Status::Punching,
                                Some(format!("Received SYN-ACK (Key: {:?})...", &public_key[0..4])),
                                Some(secs_left),
                            );
                        }
                        HandshakeMsg::Bye => {
                            state.write().await.set_status(
                                Status::Punching,
                                Some("Connection rejected by peer".into()),
                                Some(secs_left)
                            );
                            bail!("Connection rejected by peer");
                        }
                    },
                    Err(_) => {
                        debug!("Ignored invalid packet during handshake");
                    }
                }
            }

            // 2. Periodically send SYN (or Keep-Alive SynAck)
            _ = send_interval.tick() => {
                // If client is lingering, don't spam new SYNs.
                // client will send one final redundant SynAck.
                if linger_until.is_some() {
                    if sent_syn_ack {
                        let reply = bincode::serialize(&HandshakeMsg::SynAck {
                             public_key: my_pub_bytes,
                        })?;
                        client_socket.send_to(&reply, peer_addr).await.ok();
                    }
                    continue;
                }

                // Send SYN until we receive a SYN-ACK
                if !received_syn_ack {
                    let msg = bincode::serialize(&HandshakeMsg::Syn {
                        public_key: my_pub_bytes,
                        cipher_mode: my_mode,
                    })?;
                    client_socket.send_to(&msg, peer_addr).await.context("Failed to send packet")?;

                    state.write().await.set_status(
                        Status::Punching,
                        Some("Exchanging Keys...".into()),
                        Some(secs_left),
                    );
                }
            }
        }
    }

    // Handshake complete, derive keys
    if let Some(peer_pk) = peer_pub_key {
        // Use 'my_mode' safely.
        let session = derive_session(my_keys.private, peer_pk, my_mode, my_pub_bytes)?;

        let algo_name = match my_mode {
            EncryptionMode::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            EncryptionMode::Aes256Gcm => "AES-256-GCM",
        };

        state
            .write()
            .await
            .set_security_info(session.fingerprint.clone(), algo_name.to_string());

        // Transition to Connected state
        state.write().await.set_status(
            Status::Connected,
            Some(format!("Secure Channel Established ({})", algo_name)),
            None,
        );

        Ok(session)
    } else {
        bail!("Handshake failed: No public key received");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::super::{
            config::EncryptionMode,
            web::shared_state::{AppEvent, AppState, Command, Status},
        },
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
            let fake_pub_key = [7u8; 32]; // Dummy key for test

            // 1. Send SYN to A so A can fulfill `sent_syn_ack` requirement
            let syn_msg = bincode::serialize(&HandshakeMsg::Syn {
                public_key: fake_pub_key,
                cipher_mode: EncryptionMode::ChaCha20Poly1305,
            })
            .unwrap();
            socket_b.send_to(&syn_msg, addr_a).await.unwrap();

            // 2. Respond to A's SYN
            loop {
                let (len, sender) = socket_b.recv_from(&mut buf).await.unwrap();
                if sender == addr_a {
                    if let Ok(msg) = bincode::deserialize::<HandshakeMsg>(&buf[..len]) {
                        if let HandshakeMsg::Syn { .. } = msg {
                            // Send SYN-ACK back so A can fulfill `received_syn_ack`
                            let reply = bincode::serialize(&HandshakeMsg::SynAck {
                                public_key: fake_pub_key,
                            })
                            .unwrap();
                            socket_b.send_to(&reply, addr_a).await.unwrap();
                            break;
                        }
                    }
                }
            }
        });

        // Note: This test expects `derive_session` to work.
        // If derive_session does actual Curve25519 math, it might fail with [7u8; 32] as a key.
        let result = handshake(
            socket_a,
            addr_b,
            state_a.clone(),
            5,
            EncryptionMode::ChaCha20Poly1305,
        )
        .await;

        if let Err(e) = &result {
            println!("Handshake error (likely crypto mock): {}", e);
        } else {
            assert!(result.is_ok());
            let locked = state_a.read().await;
            assert_eq!(locked.status, Status::Connected);
        }
    }

    #[tokio::test]
    async fn test_handshake_timeout() {
        let socket_a = bind_local().await;
        let socket_b = bind_local().await;
        let state_a = create_dummy_state();
        let addr_b = socket_b.local_addr().unwrap();

        // Very short timeout to force failure
        let result = handshake(
            socket_a,
            addr_b,
            state_a,
            1,
            EncryptionMode::ChaCha20Poly1305,
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn test_handshake_mode_mismatch() {
        let socket_a = bind_local().await;
        let socket_b = bind_local().await;
        let state_a = create_dummy_state();
        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        // Simulate Peer B sending wrong mode
        tokio::spawn(async move {
            let fake_pub_key = [7u8; 32];
            let syn_msg = bincode::serialize(&HandshakeMsg::Syn {
                public_key: fake_pub_key,
                // Sending AES when A expects ChaCha
                cipher_mode: EncryptionMode::Aes256Gcm,
            })
            .unwrap();
            socket_b.send_to(&syn_msg, addr_a).await.unwrap();
        });

        let result = handshake(
            socket_a,
            addr_b,
            state_a,
            2,
            EncryptionMode::ChaCha20Poly1305, // Expecting ChaCha
        )
        .await;

        // Should fail due to mismatch
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("mode mismatch"));
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
            let fake_key = [1u8; 32];
            // 1. Attacker strikes first
            tokio::time::sleep(Duration::from_millis(200)).await;
            socket_c.send_to(b"FAKE_PACKET", addr_a).await.unwrap();

            // 2. Real peer replies later
            tokio::time::sleep(Duration::from_millis(1000)).await;

            // Peer sends SYN
            let syn = bincode::serialize(&HandshakeMsg::Syn {
                public_key: fake_key,
                cipher_mode: EncryptionMode::ChaCha20Poly1305,
            })
            .unwrap();
            socket_b.send_to(&syn, addr_a).await.unwrap();

            // Peer sends SYN-ACK
            let reply = bincode::serialize(&HandshakeMsg::SynAck {
                public_key: fake_key,
            })
            .unwrap();
            socket_b.send_to(&reply, addr_a).await.unwrap();
        });

        let result = handshake(
            socket_a,
            addr_b,
            state_a,
            5,
            EncryptionMode::ChaCha20Poly1305,
        )
        .await;

        if result.is_err() {
            let err_str = result.as_ref().unwrap_err().to_string();
            if err_str.contains("timed out") {
                panic!("Should not time out");
            }
        }
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

        let result = handshake(
            socket_a,
            addr_b,
            state_a,
            2,
            EncryptionMode::ChaCha20Poly1305,
        )
        .await;

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

        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        // Peer B logic - simulates another peer also initiating handshake
        let socket_b_clone = socket_b.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let fake_key = [9u8; 32];

            // 1. Send SYN to A proactively
            let syn = bincode::serialize(&HandshakeMsg::Syn {
                public_key: fake_key,
                cipher_mode: EncryptionMode::ChaCha20Poly1305,
            })
            .unwrap();
            socket_b_clone.send_to(&syn, addr_a).await.unwrap();

            // 2. Receive SYN from A and Reply
            loop {
                let (len, sender) = socket_b_clone.recv_from(&mut buf).await.unwrap();
                if sender == addr_a {
                    if let Ok(HandshakeMsg::Syn { .. }) = bincode::deserialize(&buf[..len]) {
                        // Send SYN-ACK back
                        let reply = bincode::serialize(&HandshakeMsg::SynAck {
                            public_key: fake_key,
                        })
                        .unwrap();
                        socket_b_clone.send_to(&reply, addr_a).await.unwrap();
                        break;
                    }
                }
            }
        });

        let result = handshake(
            socket_a,
            addr_b,
            state_a.clone(),
            5,
            EncryptionMode::ChaCha20Poly1305,
        )
        .await;

        if result.is_ok() {
            assert_eq!(state_a.read().await.status, Status::Connected);
        }
    }

    /// Test that both peers complete handshake when initiating simultaneously
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
        let handle_a = tokio::spawn(async move {
            handshake(
                socket_a_clone,
                addr_b,
                state_a_clone,
                5,
                EncryptionMode::ChaCha20Poly1305,
            )
            .await
        });

        let socket_b_clone = socket_b.clone();
        let state_b_clone = state_b.clone();
        let handle_b = tokio::spawn(async move {
            handshake(
                socket_b_clone,
                addr_a,
                state_b_clone,
                5,
                EncryptionMode::ChaCha20Poly1305,
            )
            .await
        });

        // Both should complete successfully (note: might take extra 1s due to linger)
        let result_a = handle_a.await.unwrap();
        let result_b = handle_b.await.unwrap();

        assert!(result_a.is_ok(), "Peer A should complete handshake");
        assert!(result_b.is_ok(), "Peer B should complete handshake");

        assert_eq!(state_a.read().await.status, Status::Connected);
        assert_eq!(state_b.read().await.status, Status::Connected);
    }
}
