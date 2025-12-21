//! Web server module for GhostLink.
//!
//! This module handles the HTTP layer of the application. It serves:
//! 1. The Static UI files (HTML/JS/CSS) from the `static/` directory.
//! 2. The API endpoints (e.g., status, configuration) for the frontend.

use super::shared_state::{Command, SharedState, Status};
use anyhow::Result;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};
use tower_http::{cors::CorsLayer, services::ServeDir};
use tracing::debug;

/// Starts the HTTP server on the specified port.
///
/// # Arguments
///
/// * `shared_state` - The thread safe application state.
/// * `port` - The port number to listen on (e.g., 8080).
///
/// # Returns
///
/// * `Ok(())` - If the server runs and stops gracefully.
/// * `Err` - If binding the port fails.
pub async fn serve(shared_state: SharedState, port: u16) -> Result<()> {
    let app = router(shared_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    tracing::info!("Web UI available at http://{}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

/// Creates the Axum Router with all routes and middleware configured.
///
/// # Arguments
/// * `shared_state` - The thread safe application state.
pub fn router(shared_state: SharedState) -> Router {
    Router::new()
        .route("/api/ip", get(get_ip))
        .route("/api/status", get(get_status))
        .route("/api/connect", post(post_peer_ip))
        // Serve the "static" directory for all non-API requests
        .fallback_service(ServeDir::new("static").append_index_html_on_directories(true))
        .layer(CorsLayer::permissive())
        .with_state(shared_state)
}

/// Handler for `GET /api/ip`
///
/// Returns the public ip and port of the local node.
async fn get_ip(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let data = state.read().await;
    Json(json!({
        "public_ip": data.public_ip,
    }))
}

/// Handler for `GET /api/status`.
///
/// Returns the current connection state of the application.
///
/// # Returns
/// JSON object: `{ "status": "disconnected" | "punching" | "connected" }`
async fn get_status(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let data = state.read().await;
    Json(json!({
        "status": data.status,
    }))
}

#[derive(Debug, Deserialize)]
struct ConnectionRequest {
    ip: String,
    port: u16,
}

/// Handler for `POST /api/connect`.
///
/// Initiates a P2P connection to the specified peer.
///
/// # Arguments
/// * `input` - JSON payload containing `ip` (String) and `port` (u16).
///
/// # Returns
/// * `200 OK` - If the connection request was received (process starts asynchronously).
/// * `422 Unprocessable Entity` - If the JSON input is invalid (wrong types).
async fn post_peer_ip(
    State(state): State<SharedState>,
    Json(input): Json<ConnectionRequest>,
) -> Result<(), (StatusCode, String)> {
    debug!("peer to connect: {}:{}", input.ip, input.port);

    // check if peer is allowed to connect
    if state.read().await.status != Status::Disconnected {
        return Err((
            StatusCode::BAD_REQUEST,
            "Already connecting/connected to a peer".into(),
        ));
    }

    // build SocketAddr
    let ip_addr = SocketAddr::new(
        IpAddr::V4(
            Ipv4Addr::from_str(&input.ip).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?,
        ),
        input.port,
    );
    // update peer ip to shared state
    {
        let mut data = state.write().await;
        data.peer_ip = Some(ip_addr);
    }

    // send controller `ConnectPeer` command
    let tx = { state.read().await.cmd_tx.clone() };
    if let Err(e) = tx.send(Command::ConnectPeer).await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Controller unavailable: {e}"),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::shared_state::{AppState, Status};
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use serde_json::{Value, json};
    use std::sync::Arc;
    use tokio::sync::{RwLock, mpsc};
    use tower::ServiceExt;

    /// Helper to create a fresh state for each test
    fn create_test_state() -> SharedState {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(32);
        // listen to cmd_rx and do nothing
        tokio::spawn(async move { while let Some(_cmd) = cmd_rx.recv().await {} });

        Arc::new(RwLock::new(AppState::new(
            None,
            Status::Disconnected,
            None,
            cmd_tx,
        )))
    }

    /// Checks that before STUN runs (when public_ip is None), the `/api/ip` endpoint
    /// correctly returns `null` instead of crashing or returning an empty string.
    #[tokio::test]
    async fn test_get_ip_initial_is_null() {
        let state = create_test_state();
        let app = router(state);

        // 1. Create a mock request
        let request = Request::builder()
            .uri("/api/ip")
            .body(Body::empty())
            .unwrap();

        // 2. Send it to the router
        let response = app.oneshot(request).await.unwrap();

        // 3. Assertions
        assert_eq!(response.status(), StatusCode::OK);

        // Parse JSON body
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(body_json, json!({ "public_ip": null }));
    }

    /// Manually forces the internal state to `Punching`, then calls the API to ensure
    /// the JSON response accurately reflects that change. This proves the "Shared State" logic works.
    #[tokio::test]
    async fn test_get_status_returns_current_state() {
        let state = create_test_state();

        // Simulate a state change
        {
            let mut guard = state.write().await;
            guard.status = Status::_Punching;
        }

        let app = router(state);

        let request = Request::builder()
            .uri("/api/status")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();

        // Matches the enum variant name serialization
        assert_eq!(body_json, json!({ "status": "_Punching" }));
    }

    /// Sends a valid JSON packet (IP + Port) to `/api/connect` to confirm the server
    /// accepts valid connection requests with a `200 OK`.
    #[tokio::test]
    async fn test_post_connect_valid_payload() {
        let state = create_test_state();
        let app = router(state);

        // 1. Create a valid JSON payload
        let payload = json!({
            "ip": "192.168.1.50",
            "port": 9000
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connect")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();

        // 2. Send request
        let response = app.oneshot(request).await.unwrap();

        // 3. Expect 200 OK
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Sends broken JSON (missing the "port") to confirm the server rejects it with
    /// a `422 Unprocessable Entity` error, ensuring the app doesn't crash on bad input.
    #[tokio::test]
    async fn test_post_connect_invalid_payload_fails() {
        let state = create_test_state();
        let app = router(state);

        // 1. Create INVALID payload (missing "port")
        let payload = json!({
            "ip": "192.168.1.50"
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connect")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // 2. Expect 422 Unprocessable Entity (Standard Axum error for bad JSON)
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// Ensures that if the app is already `Punching` or `Connected`,
    /// a new connection request is rejected with `400 Bad Request`.
    #[tokio::test]
    async fn test_post_connect_fails_when_busy() {
        let state = create_test_state();

        // 1. Simulate that we are already busy
        {
            let mut guard = state.write().await;
            guard.status = Status::_Connected;
        }

        let app = router(state);

        let payload = json!({
            "ip": "192.168.1.55",
            "port": 9000
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connect")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // 2. Expect rejection
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        // The error message comes as a plain string in the body
        assert_eq!(body_bytes, "Already connecting/connected to a peer");
    }

    /// Sends a malformed IP string (e.g., "invalid-ip") to ensure the
    /// server catches the parsing error and returns `400 Bad Request`.
    #[tokio::test]
    async fn test_post_connect_fails_on_invalid_ip() {
        let state = create_test_state();
        let app = router(state);

        let payload = json!({
            "ip": "not-an-ip-address",
            "port": 9000
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connect")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
