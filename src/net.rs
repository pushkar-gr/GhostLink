//! Network utilities for GhostLink.
//!
//! Provides NAT traversal and public IP discovery using STUN.

use super::web::shared_state::NatType;
use anyhow::{Context, Result, bail};
use std::net::{IpAddr, SocketAddr};
use stun::{
    agent::TransactionId,
    message::{BINDING_REQUEST, Getter, Message},
    xoraddr::XorMappedAddress,
};
use tokio::{
    net::UdpSocket,
    time::{Duration, timeout},
};
use tracing::debug;

/// Duration to wait for STUN response before timing out.
const STUN_TIMEOUT: Duration = Duration::from_secs(3);

/// Resolves local IP address using DNS server.
///
/// Connecting to remote address causes OS to select appropriate local interface and IP.
///
/// # Returns
///
/// * `Ok(SocketAddr)` - Local IP and port.
/// * `Err` - Resolution failed.
pub async fn get_local_ip(local_port: u16) -> Result<SocketAddr> {
    // Connect to Google's public DNS
    let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;
    socket.connect("8.8.8.8:80").await?;
    let local_addr = socket.local_addr()?;

    // Replace ephemeral port with actual listening port
    let local_ip = match local_addr.ip() {
        IpAddr::V4(ip) => SocketAddr::new(IpAddr::V4(ip), local_port),
        IpAddr::V6(ip) => SocketAddr::new(IpAddr::V6(ip), local_port),
    };

    Ok(local_ip)
}

/// Discovers public IP and port using STUN.
///
/// # Workflow
///
/// 1. Resolves STUN server DNS.
/// 2. Sends BINDING_REQUEST.
/// 3. Waits for response (3 second timeout).
/// 4. Validates transaction ID.
/// 5. Extracts public address.
///
/// # Arguments
///
/// * `socket` - Bound UDP socket.
/// * `stun_server` - STUN server address (e.g., "stun.l.google.com:19302").
///
/// # Returns
///
/// * `Ok(SocketAddr)` - Public IP and port.
/// * `Err` - DNS, network, or STUN validation failed.
pub async fn resolve_public_ip(
    socket: &UdpSocket,
    stun_server: impl AsRef<str>,
) -> Result<SocketAddr> {
    let stun_server = stun_server.as_ref();
    debug!("Querying STUN server: {}", stun_server);

    // 1. Determine socket type (IPv4 or IPv6)
    let local_addr = socket
        .local_addr()
        .context("Could not get local socket address")?;
    let is_ipv4_socket = local_addr.is_ipv4();

    // 2. Resolve DNS for STUN server
    let mut addrs = tokio::net::lookup_host(stun_server)
        .await
        .context(format!("Failed to resolve DNS for {}", stun_server))?;

    // 3. Filter addresses compatible with socket type
    let target_addr = addrs
        .find(|addr| {
            if is_ipv4_socket {
                addr.is_ipv4()
            } else {
                addr.is_ipv6()
            }
        })
        .context(format!(
            "STUN server {} has no addresses compatible with socket (Protocol Mismatch)",
            stun_server
        ))?;

    // Build STUN binding request
    let mut msg = Message::new();
    msg.build(&[Box::<TransactionId>::default(), Box::new(BINDING_REQUEST)])?;

    let expected_tx_id = msg.transaction_id;

    // 4. Send request
    socket
        .send_to(&msg.raw, target_addr)
        .await
        .context("Failed to send STUN request")?;

    // 5. Wait for response with timeout (UDP packets can be lost)
    let mut buf = [0u8; 1024];

    let (len, sender_addr) = timeout(STUN_TIMEOUT, socket.recv_from(&mut buf))
        .await
        .context("STUN request timed out")?
        .context("Failed to receive STUN response")?;

    debug!("Received {} bytes from {}", len, sender_addr);

    // 6. Parse and validate response
    let mut response = Message::new();
    response.unmarshal_binary(&buf[..len])?;

    if response.transaction_id != expected_tx_id {
        bail!(
            "Security Mismatch: Expected Transaction ID {:?}, but got {:?}",
            expected_tx_id,
            response.transaction_id
        );
    }

    // 7. Extract public IP
    let mut xor_addr = XorMappedAddress::default();
    xor_addr
        .get_from(&response)
        .context("STUN response did not contain XOR-MAPPED-ADDRESS")?;

    let public_addr = SocketAddr::new(xor_addr.ip, xor_addr.port);
    debug!("Public IP resolved: {}", public_addr);

    Ok(public_addr)
}

/// Detects NAT type by querying second STUN server.
///
/// Compares public port from two different STUN servers:
/// - Same port → Cone NAT (P2P-friendly).
/// - Different port → Symmetric NAT (P2P-difficult).
///
/// # Arguments
///
/// * `socket` - Bound UDP socket.
/// * `stun_server` - Second STUN server address.
/// * `prev_addr` - Address from first STUN query.
///
/// # Returns
///
/// NAT type: Cone, Symmetric, or Unknown.
pub async fn get_nat_type(
    socket: &UdpSocket,
    stun_server: impl AsRef<str>,
    prev_addr: SocketAddr,
) -> NatType {
    // Resolve public IP using new STUN server
    resolve_public_ip(socket, stun_server).await.map_or_else(
        // Return Unknown if any error
        |_| NatType::Unknown,
        |public_ip| {
            // Return NAT type based on response
            if prev_addr == public_ip {
                NatType::Cone
            } else {
                NatType::Symmetric
            }
        },
    )
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

        // Expect a timeout error roughly after STUN_TIMEOUT
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

    /// Simulates a scenario where the second STUN server sees a DIFFERENT port than the first one.
    /// This indicates the router is assigning new external ports for each destination (Symmetric).
    #[tokio::test]
    async fn test_get_nat_type_symmetric() {
        // 1. Setup Mock Server 2 (Simulating a second STUN server)
        let mock_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = mock_server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (len, client_addr) = mock_server.recv_from(&mut buf).await.unwrap();

            let mut req = Message::new();
            req.unmarshal_binary(&buf[..len]).unwrap();

            // Reply with a DIFFERENT port than what the client expects from the first server
            let mut resp = Message::new();
            resp.transaction_id = req.transaction_id;
            resp.build(&[
                Box::new(BINDING_SUCCESS),
                Box::new(XorMappedAddress {
                    ip: "127.0.0.1".parse().unwrap(),
                    port: 8888, // Different port
                }),
            ])
            .unwrap();

            mock_server.send_to(&resp.raw, client_addr).await.unwrap();
        });

        // 2. Setup Client
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // 3. Define "Previous Address" (Result from STUN 1)
        // Pretend STUN 1 said we are on port 9999.
        let prev_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // 4. Run Detection
        // Since STUN 2 returns port 8888, and 8888 != 9999, it should be Symmetric.
        let nat_type = get_nat_type(&socket, server_addr.to_string(), prev_addr).await;

        assert_eq!(nat_type, NatType::Symmetric);
    }

    /// Simulates a scenario where the second STUN server sees the SAME port as the first one.
    /// This indicates the router reuses the mapping (Cone).
    #[tokio::test]
    async fn test_get_nat_type_cone() {
        let mock_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = mock_server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (len, client_addr) = mock_server.recv_from(&mut buf).await.unwrap();

            let mut req = Message::new();
            req.unmarshal_binary(&buf[..len]).unwrap();

            // Reply with the SAME port as prev_addr
            let mut resp = Message::new();
            resp.transaction_id = req.transaction_id;
            resp.build(&[
                Box::new(BINDING_SUCCESS),
                Box::new(XorMappedAddress {
                    ip: "127.0.0.1".parse().unwrap(),
                    port: 9999, // Same port
                }),
            ])
            .unwrap();

            mock_server.send_to(&resp.raw, client_addr).await.unwrap();
        });

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let prev_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let nat_type = get_nat_type(&socket, server_addr.to_string(), prev_addr).await;

        assert_eq!(nat_type, NatType::Cone);
    }

    /// If the second STUN query fails (timeout/DNS), it should default to `Unknown` rather than crashing.
    #[tokio::test]
    async fn test_get_nat_type_unknown_on_failure() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let prev_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Point to a non-existent server to force a timeout/error
        let nat_type = get_nat_type(&socket, "127.0.0.1:0", prev_addr).await;

        assert_eq!(nat_type, NatType::Unknown);
    }
}
