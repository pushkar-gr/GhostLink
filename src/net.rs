//! Network module for GhostLink.
//!
//! This module handles low-level networking operations, specifically
//! NAT Traversal and Public IP discovery using the STUN protocol.

use anyhow::{Context, Result, bail};
use std::{net::SocketAddr, sync::Arc};
use stun::{
    agent::TransactionId,
    message::{BINDING_REQUEST, Getter, Message},
    xoraddr::XorMappedAddress,
};
use tokio::net::UdpSocket;
use tracing::{debug, info};

/// Resolves public IP and port of the local machine by querying a public STUN server.
///
/// 1. Resolves DNS of the STUN server.
/// 2. Sends a STUN `BINDING_REQUEST` using given UDP socket.
/// 3. Waites for `BINDING_SUCCESS` response.
/// 4. Validates the Transaction ID to ensure security.
/// 5. Extracts the `XorMappedAddress` from response.
///
/// # Arguments
///
/// * `socket` - A referance to shared `UdpSocket`. This must be bound before calling this function.
/// * `stun_server` - The address of the STUN server (e.g., "stun.l.google.com:19302").
///
/// # Returns
///
/// * `Ok(SocketAddr)` - The public IP and port of local machine.
/// * `Err` - If DNS failes, the server is unreachable, or the response is invalide.
pub async fn resolve_public_ip(socket: &Arc<UdpSocket>, stun_server: &str) -> Result<SocketAddr> {
    info!("Resolving public IP via {}", stun_server);

    // 1. Resolve DNS for the STUN server.
    let mut addrs = tokio::net::lookup_host(stun_server)
        .await
        .context(format!("Failed to resolve DNS for {}", stun_server))?;
    // Use resolved IP address
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

    // 3. Wait for response
    let mut buf = [0u8; 1024];
    let (len, sender_addr) = socket
        .recv_from(&mut buf)
        .await
        .context("Failed to receive STUN response")?;

    debug!("Recieved {} bytes from {}", len, sender_addr);

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

    // 5. Extrack the public IP
    let mut xor_addr = XorMappedAddress::default();
    xor_addr
        .get_from(&response)
        .context("STUN response did not contain XOR-MAPPED-ADDRESS")?;

    let public_addr = SocketAddr::new(xor_addr.ip, xor_addr.port);
    info!("Public IP: {}", public_addr);

    Ok(public_addr)
}

#[cfg(test)]
mod test {
    use super::*;
    use stun::message::BINDING_SUCCESS;

    /// Verifies that the resolve_public_ip function correctly handles a STNU response. by spawning
    /// a local mock server.
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
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let result = resolve_public_ip(&socket, &server_addr.to_string()).await;

        // Verify
        assert!(result.is_ok());
        let ip = result.unwrap();
        assert_eq!(ip.port(), 9999);
    }

    /// Verifies that resolve_public_ip fails when DNS resolution fails.
    #[tokio::test]
    async fn test_resolve_public_ip_dns_failure() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        // Use an invalid hostname that will fail DNS resolution
        let result = resolve_public_ip(&socket, "invalid.hostname.that.does.not.exist:19302").await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Failed to resolve DNS") || err_msg.contains("failed to lookup"));
    }

    /// Verifies that resolve_public_ip rejects responses with mismatched transaction IDs.
    #[tokio::test]
    async fn test_resolve_public_ip_transaction_id_mismatch() {
        let mock_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = mock_server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (len, client_addr) = mock_server.recv_from(&mut buf).await.unwrap();

            // Parse the request to get its transaction ID
            let mut req = Message::new();
            req.unmarshal_binary(&buf[..len]).unwrap();

            // Create a response with a DIFFERENT transaction ID
            let mut resp = Message::new();
            // Manually create a different transaction ID by manipulating bytes
            let mut new_tx_id = req.transaction_id;
            new_tx_id.0[0] = new_tx_id.0[0].wrapping_add(1); // Change first byte
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

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let result = resolve_public_ip(&socket, &server_addr.to_string()).await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Security Mismatch") || err_msg.contains("Transaction ID"));
    }

    /// Verifies that resolve_public_ip fails when response lacks XOR-MAPPED-ADDRESS.
    #[tokio::test]
    async fn test_resolve_public_ip_missing_xor_address() {
        let mock_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = mock_server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (len, client_addr) = mock_server.recv_from(&mut buf).await.unwrap();

            let mut req = Message::new();
            req.unmarshal_binary(&buf[..len]).unwrap();

            // Send response WITHOUT XorMappedAddress attribute
            let mut resp = Message::new();
            resp.transaction_id = req.transaction_id;
            resp.build(&[Box::new(BINDING_SUCCESS)]).unwrap();

            mock_server.send_to(&resp.raw, client_addr).await.unwrap();
        });

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let result = resolve_public_ip(&socket, &server_addr.to_string()).await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("XOR-MAPPED-ADDRESS") || err_msg.contains("did not contain"));
    }
}
