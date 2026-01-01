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
use tracing::{debug, info}; // Removed 'warn'

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

    let my_keys = KeyPair::generate();
    let my_pub_bytes = my_keys.public.to_bytes();

    let mut send_interval = tokio::time::interval(Duration::from_millis(500));
    send_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    #[allow(unused_assignments)]
    let mut peer_pub_key: Option<[u8; 32]> = None;
    let mut negotiated_mode = my_mode;
    let mut received_syn_ack = false;
    let mut sent_syn_ack = false;

    info!("Starting secure handshake with {}", peer_addr);

    {
        let mut guard = state.write().await;
        guard.set_status(
            Status::Punching,
            Some("Handshaking (Keys Generated)...".to_string()),
            Some(timeout_secs),
        );
    }

    loop {
        let elapsed = start_time.elapsed();
        if elapsed > timeout {
            let msg = format!("Handshake timed out with {}", peer_addr);
            state
                .write()
                .await
                .set_status(Status::Punching, Some(msg.clone()), Some(0));
            bail!(msg);
        }

        let secs_left = timeout.as_secs().saturating_sub(elapsed.as_secs());

        tokio::select! {
            result = client_socket.recv_from(&mut buf) => {
                let (len, sender) = result.context("Socket read error")?;

                if sender != peer_addr {
                    continue;
                }

                match bincode::deserialize::<HandshakeMsg>(&buf[..len]) {
                    Ok(msg) => match msg {
                        HandshakeMsg::Syn { public_key, cipher_mode } => {
                            info!("Received SYN from {}. Mode: {:?}.", sender, cipher_mode);
                            negotiated_mode = cipher_mode;
                            peer_pub_key = Some(public_key);

                            let reply = bincode::serialize(&HandshakeMsg::SynAck {
                                public_key: my_pub_bytes,
                            })?;
                            client_socket.send_to(&reply, peer_addr).await?;

                            state.write().await.set_status(
                                Status::Punching,
                                Some(format!("Received SYN (Key: {:?})...", &public_key[0..4])),
                                Some(secs_left),
                            );

                            sent_syn_ack = true;
                            if received_syn_ack {
                                break;
                            }
                        }
                        HandshakeMsg::SynAck { public_key } => {
                            info!("Received SYN-ACK from {}.", sender);
                            peer_pub_key = Some(public_key);

                            state.write().await.set_status(
                                Status::Punching,
                                Some(format!("Received SYN-ACK (Key: {:?})...", &public_key[0..4])),
                                Some(secs_left),
                            );

                            received_syn_ack = true;
                            if sent_syn_ack {
                                break;
                            }
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

            _ = send_interval.tick() => {
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

    if let Some(peer_pk) = peer_pub_key {
        let session = derive_session(my_keys.private, peer_pk, negotiated_mode, my_pub_bytes)?;

        let algo_name = match negotiated_mode {
            EncryptionMode::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            EncryptionMode::Aes256Gcm => "AES-256-GCM",
        };

        state
            .write()
            .await
            .set_security_info(session.fingerprint.clone(), algo_name.to_string());

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
