//! Network module for GhostLink.
//!
//! This module handles low-level networking operations, specifically
//! NAT Traversal and Public IP discovery using the STUN protocol.

use anyhow::{Context, Result, bail};
use std::net::SocketAddr;
use stun::{
    agent::TransactionId,
    message::{BINDING_REQUEST, Getter, Message},
    xoraddr::XorMappedAddress,
};
use tokio::{
    net::UdpSocket,
    time::{Duration, timeout},
};
use tracing::{debug, info};

/// The duration to wait for a STUN response before timing out.
const STUN_TIMEOUT: Duration = Duration::from_secs(3);

/// Resolves the public IP and port of the local machine by querying a public STUN server.
///
/// # Workflow
/// 1. Resolves DNS of the provided STUN server.
/// 2. Sends a STUN `BINDING_REQUEST` using the provided UDP socket.
/// 3. Waits for a `BINDING_SUCCESS` response (with a 3-second timeout).
/// 4. Validates the Transaction ID to prevent spoofing.
/// 5. Extracts the `XorMappedAddress` (public IP) from the response.
///
/// # Arguments
///
/// * `socket` - A reference to the UDP socket. The socket must be bound before calling.
/// * `stun_server` - The address of the STUN server (e.g., "stun.l.google.com:19302").
///
/// # Returns
///
/// * `Ok(SocketAddr)` - The public IP and port of the local machine.
/// * `Err` - If DNS fails, the server is unreachable, the request times out, or the response is invalid.
pub async fn resolve_public_ip(
    socket: &UdpSocket,
    stun_server: impl AsRef<str>,
) -> Result<SocketAddr> {
    let stun_server = stun_server.as_ref();
    info!("Resolving public IP via {}", stun_server);

    // 1. Resolve DNS for the STUN server.
    let mut addrs = tokio::net::lookup_host(stun_server)
        .await
        .context(format!("Failed to resolve DNS for {}", stun_server))?;

    // Use the first resolved IP address
    let target_addr = addrs
        .next()
        .context("STUN server domain name did not resolve to any IP address")?;

    // Build the STUN binding request
    let mut msg = Message::new();
    msg.build(&[Box::<TransactionId>::default(), Box::new(BINDING_REQUEST)])?;

    let expected_tx_id = msg.transaction_id;

    // 2. Send the request
    socket
        .send_to(&msg.raw, target_addr)
        .await
        .context("Failed to send STUN request")?;

    // 3. Wait for response with timeout
    let mut buf = [0u8; 1024];

    // We use a timeout here because UDP packets can be lost, and we don't want to hang forever.
    let (len, sender_addr) = timeout(STUN_TIMEOUT, socket.recv_from(&mut buf))
        .await
        .context("STUN request timed out")?
        .context("Failed to receive STUN response")?;

    debug!("Received {} bytes from {}", len, sender_addr);

    // 4. Parse and validate response
    let mut response = Message::new();
    response.unmarshal_binary(&buf[..len])?;

    if response.transaction_id != expected_tx_id {
        bail!(
            "Security Mismatch: Expected Transaction ID {:?}, but got {:?}",
            expected_tx_id,
            response.transaction_id
        );
    }

    // 5. Extract the public IP
    let mut xor_addr = XorMappedAddress::default();
    xor_addr
        .get_from(&response)
        .context("STUN response did not contain XOR-MAPPED-ADDRESS")?;

    let public_addr = SocketAddr::new(xor_addr.ip, xor_addr.port);
    debug!("Public IP resolved: {}", public_addr);

    Ok(public_addr)
}

#[cfg(test)]
mod test {
    use super::*;
    use stun::message::BINDING_SUCCESS;

    /// Verifies that the resolve_public_ip function correctly handles a valid STUN response.
    #[tokio::test]
    async fn test_resolve_public_ip_mock() {
        // Setup a mock server
        let mock_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = mock_server.local_addr().unwrap();

        // Spawn server task
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (len, client_addr) = mock_server.recv_from(&mut buf).await.unwrap();

            // Parse request
            let mut req = Message::new();
            req.unmarshal_binary(&buf[..len]).unwrap();

            // Send valid response
            let mut resp = Message::new();
            resp.transaction_id = req.transaction_id;
            resp.build(&[
                Box::new(BINDING_SUCCESS),
                Box::new(XorMappedAddress {
                    ip: "127.0.0.1".parse().unwrap(),
                    port: 9999,
                }),
            ])
            .unwrap();

            mock_server.send_to(&resp.raw, client_addr).await.unwrap();
        });

        // Run client
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = resolve_public_ip(&socket, server_addr.to_string()).await;

        // Verify
        assert!(result.is_ok());
        let ip = result.unwrap();
        assert_eq!(ip.port(), 9999);
    }

    /// Verifies that resolve_public_ip fails gracefully when DNS resolution fails.
    #[tokio::test]
    async fn test_resolve_public_ip_dns_failure() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Use an invalid hostname that will fail DNS resolution
        let result = resolve_public_ip(&socket, "invalid.hostname.that.does.not.exist:19302").await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Failed to resolve DNS") || err_msg.contains("failed to lookup"));
    }

    /// Verifies that resolve_public_ip times out if no response is received.
    #[tokio::test]
    async fn test_resolve_public_ip_timeout() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Bind a "server" that never replies
        let mock_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = mock_server.local_addr().unwrap();

        // We expect a timeout error roughly after STUN_TIMEOUT
        let result = resolve_public_ip(&socket, server_addr.to_string()).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "STUN request timed out");
    }

    /// Verifies that resolve_public_ip rejects responses with mismatched transaction IDs.
    #[tokio::test]
    async fn test_resolve_public_ip_transaction_id_mismatch() {
        let mock_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = mock_server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (len, client_addr) = mock_server.recv_from(&mut buf).await.unwrap();

            let mut req = Message::new();
            req.unmarshal_binary(&buf[..len]).unwrap();

            // Create a response with a DIFFERENT transaction ID
            let mut resp = Message::new();
            let mut new_tx_id = req.transaction_id;
            new_tx_id.0[0] = new_tx_id.0[0].wrapping_add(1); // Alter ID
            resp.transaction_id = new_tx_id;

            resp.build(&[
                Box::new(BINDING_SUCCESS),
                Box::new(XorMappedAddress {
                    ip: "127.0.0.1".parse().unwrap(),
                    port: 9999,
                }),
            ])
            .unwrap();

            mock_server.send_to(&resp.raw, client_addr).await.unwrap();
        });

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let result = resolve_public_ip(&socket, server_addr.to_string()).await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Security Mismatch"));
    }
}
