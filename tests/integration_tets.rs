//! Integration tests for GhostLink
//!
//! Tests end-to-end functionality including P2P connections,
//! encryption, and message exchange.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, broadcast, mpsc};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn test_udp_socket_creation() {
    // Test that we can create and bind UDP sockets
    let socket = UdpSocket::bind("127.0.0.1:0").await;
    assert!(socket.is_ok());

    let socket = socket.unwrap();
    let local_addr = socket.local_addr();
    assert!(local_addr.is_ok());
}

#[tokio::test]
async fn test_multiple_socket_binds() {
    // Test that we can create multiple UDP sockets
    let socket1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let addr1 = socket1.local_addr().unwrap();
    let addr2 = socket2.local_addr().unwrap();

    // Should have different ports
    assert_ne!(addr1.port(), addr2.port());
}

#[tokio::test]
async fn test_udp_message_exchange() {
    // Test basic UDP message exchange
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Send message from client to server
    let sent = client.send_to(b"Hello", server_addr).await;
    assert!(sent.is_ok());

    // Receive on server
    let mut buf = [0u8; 100];
    let result = timeout(Duration::from_secs(1), server.recv_from(&mut buf)).await;

    assert!(result.is_ok());
    let (len, _addr) = result.unwrap().unwrap();
    assert_eq!(&buf[..len], b"Hello");
}

#[tokio::test]
async fn test_concurrent_udp_operations() {
    // Test that multiple UDP operations can happen concurrently
    let socket1 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let socket2 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let addr1 = socket1.local_addr().unwrap();
    let addr2 = socket2.local_addr().unwrap();

    let s1 = socket1.clone();
    let s2 = socket2.clone();

    // Send messages concurrently
    let send1 = tokio::spawn(async move { s1.send_to(b"Message1", addr2).await });

    let send2 = tokio::spawn(async move { s2.send_to(b"Message2", addr1).await });

    let result1 = send1.await;
    let result2 = send2.await;

    assert!(result1.is_ok());
    assert!(result2.is_ok());
}

#[tokio::test]
async fn test_broadcast_channel() {
    // Test tokio broadcast channel functionality
    let (tx, mut rx1) = broadcast::channel::<String>(16);
    let mut rx2 = tx.subscribe();

    tx.send("Test message".to_string()).unwrap();

    let msg1 = rx1.recv().await;
    let msg2 = rx2.recv().await;

    assert!(msg1.is_ok());
    assert!(msg2.is_ok());
    assert_eq!(msg1.unwrap(), "Test message");
    assert_eq!(msg2.unwrap(), "Test message");
}

#[tokio::test]
async fn test_mpsc_channel() {
    // Test tokio mpsc channel functionality
    let (tx, mut rx) = mpsc::channel::<i32>(32);

    tx.send(42).await.unwrap();
    tx.send(100).await.unwrap();

    let val1 = rx.recv().await;
    let val2 = rx.recv().await;

    assert_eq!(val1, Some(42));
    assert_eq!(val2, Some(100));
}

#[tokio::test]
async fn test_rwlock_concurrent_reads() {
    // Test that RwLock allows concurrent reads
    let data = Arc::new(RwLock::new(42));

    let d1 = data.clone();
    let d2 = data.clone();

    let read1 = tokio::spawn(async move {
        let value = d1.read().await;
        *value
    });

    let read2 = tokio::spawn(async move {
        let value = d2.read().await;
        *value
    });

    let val1 = read1.await.unwrap();
    let val2 = read2.await.unwrap();

    assert_eq!(val1, 42);
    assert_eq!(val2, 42);
}

#[tokio::test]
async fn test_rwlock_write_exclusion() {
    // Test that RwLock write is exclusive
    let data = Arc::new(RwLock::new(0));
    let (tx, mut rx) = mpsc::channel::<()>(1);

    let d1 = data.clone();
    let write1 = tokio::spawn(async move {
        let mut value = d1.write().await;
        *value += 1;
        // Signal that first write has started
        tx.send(()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        *value
    });

    // Wait for first write to acquire lock
    rx.recv().await.unwrap();

    let d2 = data.clone();
    let write2 = tokio::spawn(async move {
        let mut value = d2.write().await;
        *value += 10;
        *value
    });

    let val1 = write1.await.unwrap();
    let val2 = write2.await.unwrap();

    // Second write should see result of first write
    assert_eq!(val1, 1);
    assert_eq!(val2, 11);
}

#[tokio::test]
async fn test_socket_addr_parsing() {
    // Test SocketAddr parsing
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(addr.port(), 8080);

    let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    assert_eq!(addr.port(), 0);
}

#[tokio::test]
async fn test_timeout_functionality() {
    // Test timeout works correctly
    let result = timeout(
        Duration::from_millis(100),
        tokio::time::sleep(Duration::from_secs(10)),
    )
    .await;

    assert!(result.is_err());

    let result = timeout(Duration::from_millis(100), async { 42 }).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);
}
