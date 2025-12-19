use anyhow::{Context, Result, bail};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    net::UdpSocket,
    time::{Duration, Instant},
};
use tracing::{info, warn};

/// Performs a UDP hole punching handshake with a remote peer.
///
/// This function tires to establish a bidirectional connection by sending "HELLOW_PUNCH" packets
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
    timeout_secs: u64,
) -> Result<()> {
    let mut buf = [0u8; 2048];
    let timeout = Duration::from_secs(timeout_secs);
    let start_time = Instant::now();
    let mut send_interval = tokio::time::interval(Duration::from_millis(500));

    info!("Starting handshake with {}", peer_addr);

    // Prevent a burst of ticks when the task is delayed.
    send_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        // Check timeout at every iteration.
        if start_time.elapsed() > timeout {
            bail!("Handshake timed out with {}", peer_addr);
        }

        tokio::select! {
            // 1. Listen to incoming packets.
            result = client_socket.recv_from(&mut buf) => {
                let (len, sender) = result.context("Socket read error")?;
                if sender == peer_addr {
                    let msg = &buf[..len];

                    if msg == b"BYE" {
                        warn!("Peer {} rejected connection (received BYE)", sender);
                        bail!("Connection rejected by peer");
                    }

                    info!("Handshake success with peer {}. received {} bytes.", sender, len);
                    return Ok(())
                } else {
                    info!("Ignored packet from unknown sender: {}", sender);
                }
            }

            // 2. Periodically send "HOLLO_PUNCH" to keep NAT mapping open
            _ = send_interval.tick() => {
                let msg = b"HOLLO_PUNCH";
                client_socket.send_to(msg, peer_addr).await.context("Failed to send packet")?;
                info!("Punched hole to {}...", peer_addr);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, time::Duration};
    use tokio::net::UdpSocket;

    /// Helper to create a socket bound to a random local port
    async fn bind_local() -> Arc<UdpSocket> {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Arc::new(socket)
    }

    /// Verifies that the handshake succeeds when the peer replies.
    /// It simulates a peer (B) waiting 500ms and then sending "HELLO_BACK".
    /// We expect `handshake` to return `Ok`.
    #[tokio::test]
    async fn test_handshake_success() {
        let socket_a = bind_local().await;
        let socket_b = bind_local().await;

        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            socket_b.send_to(b"HELLO_BACK", addr_a).await.unwrap();
        });

        let result = handshake(socket_a, addr_b, 5).await;
        assert!(result.is_ok());
    }

    /// Verifies that the function gives up if the peer is silent.
    /// We start the handshake with a short 2-second timeout against a
    /// dummy socket that never sends anything.
    /// We expect `handshake` to return `Err("Handshake timed out...")`.
    #[tokio::test]
    async fn test_handshake_timeout() {
        let socket_a = bind_local().await;
        let socket_b = bind_local().await;
        let addr_b = socket_b.local_addr().unwrap();

        let result = handshake(socket_a, addr_b, 2).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }

    /// Verifies that we ignore packets from random people.
    /// An "Attacker" (C) sends a packet first. The function should ignore it
    /// and keep waiting until the "Real Peer" (B) replies later.
    #[tokio::test]
    async fn test_handshake_ignores_wrong_sender() {
        let socket_a = bind_local().await;
        let socket_b = bind_local().await; // Real Peer
        let socket_c = bind_local().await; // Attacker

        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        tokio::spawn(async move {
            // 1. Attacker strikes first
            tokio::time::sleep(Duration::from_millis(200)).await;
            socket_c.send_to(b"FAKE_PACKET", addr_a).await.unwrap();

            // 2. Real peer replies later
            tokio::time::sleep(Duration::from_millis(1000)).await;
            socket_b.send_to(b"REAL_PACKET", addr_a).await.unwrap();
        });

        let result = handshake(socket_a, addr_b, 5).await;
        assert!(result.is_ok());
    }

    /// Verifies that we respect a peer saying "BYE".
    /// The peer sends "BYE" instead of a normal hello.
    /// We expect `handshake` to fail immediately with "Connection rejected".
    #[tokio::test]
    async fn test_handshake_rejects_bye_packet() {
        let socket_a = bind_local().await;
        let socket_b = bind_local().await;

        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            socket_b.send_to(b"BYE", addr_a).await.unwrap();
        });

        let result = handshake(socket_a, addr_b, 2).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Connection rejected by peer"
        );
    }
}
