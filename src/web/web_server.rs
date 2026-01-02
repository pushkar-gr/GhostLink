//! Web server for GhostLink.
//!
//! Provides:
//! 1. Static UI (HTML/JS/CSS)
//! 2. REST API endpoints
//! 3. Server-Sent Events (SSE) for real-time updates

use super::shared_state::{Command, SharedState, Status};
use crate::config::EncryptionMode;
use anyhow::Result;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{
        IntoResponse,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use futures::stream::Stream;
use serde::Deserialize;
use serde_json::json;
use std::{
    convert::Infallible,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};
use tokio_stream::{StreamExt, wrappers::BroadcastStream};
use tower_http::{cors::CorsLayer, services::ServeDir};
use tracing::{debug, error, info};

/// Starts the HTTP server.
///
/// # Arguments
///
/// * `shared_state` - Thread-safe application state
/// * `port` - Port to listen on
pub async fn start_web_server(shared_state: SharedState, port: u16) -> Result<()> {
    let app = router(shared_state);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    info!("Web UI available at http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Creates the Axum router with all routes and middleware.
pub fn router(shared_state: SharedState) -> Router {
    Router::new()
        // API Routes
        .route("/api/state", get(get_state))
        .route("/api/connect", post(connect_peer))
        .route("/api/disconnect", post(disconnect_peer))
        .route("/api/message", post(send_message))
        .route("/api/events", get(sse_handler))
        // Static File Serving (Fallback)
        .fallback_service(ServeDir::new("static").append_index_html_on_directories(true))
        // Middleware
        .layer(CorsLayer::permissive())
        .with_state(shared_state)
}

// --- API Handlers ---

/// Handler for `GET /api/state`.
/// Returns current application state including IPs, NAT type, and status.
async fn get_state(State(state): State<SharedState>) -> impl IntoResponse {
    let data = state.read().await;
    Json(json!({ "state": data.clone() }))
}

#[derive(Debug, Deserialize)]
struct ConnectionRequest {
    ip: String,
    port: u16,
    #[serde(default = "default_encryption_mode")]
    mode: EncryptionMode,
}

fn default_encryption_mode() -> EncryptionMode {
    EncryptionMode::ChaCha20Poly1305
}

/// Handler for `POST /api/connect`.
/// Validates peer IP and triggers connection process.
async fn connect_peer(
    State(state): State<SharedState>,
    Json(input): Json<ConnectionRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    debug!(
        "Received connection request: {}:{} (Mode: {:?})",
        input.ip, input.port, input.mode
    );

    // 1. Validate Input IP
    let ip_v4 = Ipv4Addr::from_str(&input.ip).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid IP address: {}", e),
        )
    })?;

    let peer_addr = SocketAddr::new(IpAddr::V4(ip_v4), input.port);

    // 2. Validate State & Update
    {
        let mut guard = state.write().await;
        if guard.status != Status::Disconnected {
            return Err((
                StatusCode::BAD_REQUEST,
                "Cannot connect: Node is already busy (connected or punching).".to_string(),
            ));
        }

        // Set the peer IP
        guard.set_peer_ip(peer_addr, Some("Target set via API".into()), None);
    }

    // 3. Send command to controller
    // Controller reads peer_addr from SharedState
    let cmd_tx = state.read().await.cmd_tx().clone();
    if let Err(e) = cmd_tx.send(Command::ConnectPeer).await {
        error!("Failed to send ConnectPeer command: {}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Controller Error".to_string(),
        ));
    }

    Ok(StatusCode::OK)
}

/// Handler for `POST /api/disconnect`.
/// Triggers graceful disconnection from the current peer.
async fn disconnect_peer(
    State(state): State<SharedState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    debug!("Received disconnect request");

    // Check if connected or punching
    let status = state.read().await.status;
    if status == Status::Disconnected {
        return Err((StatusCode::BAD_REQUEST, "Already disconnected".to_string()));
    }

    // Send command to controller
    let cmd_tx = state.read().await.cmd_tx().clone();
    if let Err(e) = cmd_tx.send(Command::Disconnect).await {
        error!("Failed to send Disconnect command: {}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Controller Error".to_string(),
        ));
    }

    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize)]
struct SendMessageRequest {
    message: String,
}

/// Handler for `POST /api/message`.
async fn send_message(
    State(state): State<SharedState>,
    Json(input): Json<SendMessageRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if input.message.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Message cannot be empty".into()));
    }

    // Check if connected
    if state.read().await.status != Status::Connected {
        return Err((StatusCode::BAD_REQUEST, "Not connected to a peer".into()));
    }

    // Send command to controller
    let cmd_tx = state.read().await.cmd_tx().clone();
    if let Err(e) = cmd_tx.send(Command::SendMessage(input.message)).await {
        error!("Failed to send Message command: {}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Controller Error".to_string(),
        ));
    }

    Ok(StatusCode::OK)
}

/// Handler for `GET /api/events`.
/// Establishes SSE stream for real-time state updates.
async fn sse_handler(
    State(state): State<SharedState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    debug!("New SSE client connected");

    // Create a broadcast receiver from the state
    let rx = state.read().await.subscribe_events();
    let stream = BroadcastStream::new(rx);

    // Map broadcast messages to SSE events
    let stream = stream.map(|msg| match msg {
        Ok(app_event) => {
            // Serialize the event to JSON
            let json_data = serde_json::to_string(&app_event).unwrap_or_else(|_| "{}".into());
            Ok(Event::default().data(json_data))
        }
        Err(_lagged) => {
            // Handle lagged receivers (slow clients) gracefully
            Ok(Event::default().comment("keep-alive-sync"))
        }
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(5))
            .text("keep-alive"),
    )
}

#[cfg(test)]
mod tests {
    use super::super::shared_state::{AppEvent, AppState, NatType, Status};
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use serde_json::{Value, json};
    use std::sync::Arc;
    use tokio::sync::{RwLock, broadcast, mpsc};
    use tower::ServiceExt;

    /// Helper to create a fresh state for each test.
    /// This mimics the real application startup.
    fn create_test_state() -> SharedState {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(32);
        let (event_tx, _) = broadcast::channel::<AppEvent>(32);

        // Drain the command channel to prevent it from filling up during tests
        tokio::spawn(async move { while cmd_rx.recv().await.is_some() {} });

        Arc::new(RwLock::new(AppState::new(cmd_tx, event_tx)))
    }

    /// Checks that `/api/state` returns the correct default JSON structure
    /// when the application first boots (all nulls/defaults).
    #[tokio::test]
    async fn test_get_state_initial_structure() {
        let state = create_test_state();
        let app = router(state);

        let request = Request::builder()
            .uri("/api/state")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();

        // The API returns { "state": { ... } }
        let state_obj = &body_json["state"];

        // Verify defaults
        assert_eq!(state_obj["public_ip"], Value::Null);
        assert_eq!(state_obj["peer_ip"], Value::Null);
        assert_eq!(state_obj["status"], "Disconnected");
        assert_eq!(state_obj["nat_type"], "Unknown");
    }

    /// Manually modifies the `SharedState` and verifies that `/api/state`
    /// reflects these changes (IPs, Status, NAT Type) in the JSON response.
    #[tokio::test]
    async fn test_get_state_reflects_updates() {
        let state = create_test_state();

        // 1. Manually update internal state
        {
            let mut guard = state.write().await;
            guard.public_ip = Some("203.0.113.10:8080".parse().unwrap());
            guard.peer_ip = Some("198.51.100.20:9000".parse().unwrap());
            guard.status = Status::Punching;
            guard.nat_type = NatType::Symmetric;
        }

        let app = router(state);

        let request = Request::builder()
            .uri("/api/state")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
        let state_obj = &body_json["state"];

        // 2. Verify JSON matches updates
        assert_eq!(state_obj["public_ip"], "203.0.113.10:8080");
        assert_eq!(state_obj["peer_ip"], "198.51.100.20:9000");
        assert_eq!(state_obj["status"], "Punching");
        assert_eq!(state_obj["nat_type"], "Symmetric");
    }

    #[tokio::test]
    async fn test_connect_valid_payload() {
        let state = create_test_state();
        let app = router(state.clone());

        // Updated: Added optional "mode" field (implicit test of default logic)
        let payload = json!({ "ip": "192.168.1.50", "port": 9000 });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connect")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify state update
        let peer_ip = state.read().await.peer_ip;
        assert_eq!(peer_ip.unwrap().to_string(), "192.168.1.50:9000");
    }

    #[tokio::test]
    async fn test_connect_invalid_payload_fails() {
        let state = create_test_state();
        let app = router(state);

        let payload = json!({ "ip": "192.168.1.50" }); // Missing port

        let request = Request::builder()
            .method("POST")
            .uri("/api/connect")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_connect_fails_when_busy() {
        let state = create_test_state();
        {
            state.write().await.status = Status::Connected;
        }
        let app = router(state);

        let payload = json!({ "ip": "192.168.1.55", "port": 9000 });
        let request = Request::builder()
            .method("POST")
            .uri("/api/connect")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_sse_headers() {
        let state = create_test_state();
        let app = router(state);

        let request = Request::builder()
            .uri("/api/events")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/event-stream"
        );
    }

    /// Verifies that updating public IP triggers a broadcast event.
    #[tokio::test]
    async fn test_public_ip_update_broadcasts_event() {
        let state = create_test_state();

        // Subscribe to events before updating
        let mut event_rx = state.read().await.subscribe_events();

        // Update public IP
        {
            let mut guard = state.write().await;
            guard.set_public_ip(
                "203.0.113.10:8080".parse().unwrap(),
                Some("Public IP resolved".into()),
                None,
            );
        }

        // Verify event was broadcast
        let event = event_rx.recv().await.unwrap();
        match event {
            AppEvent::Disconnected {
                state: app_state,
                message: Some(_),
            } => {
                assert_eq!(
                    app_state.public_ip.unwrap().to_string(),
                    "203.0.113.10:8080"
                );
            }
            _ => panic!("Expected Disconnected event"),
        }
    }

    /// Verifies that public IP changes are detected and broadcast correctly.
    #[tokio::test]
    async fn test_public_ip_change_detection() {
        let state = create_test_state();

        // Set initial IP
        {
            let mut guard = state.write().await;
            guard.set_public_ip(
                "203.0.113.10:8080".parse().unwrap(),
                Some("Initial IP".into()),
                None,
            );
        }

        // Subscribe after initial setup
        let mut event_rx = state.read().await.subscribe_events();

        // Change IP
        {
            let mut guard = state.write().await;
            let old_ip = guard.public_ip;
            let new_ip: SocketAddr = "203.0.113.20:8080".parse().unwrap();

            assert_ne!(old_ip, Some(new_ip));

            guard.set_public_ip(new_ip, Some("Public IP updated".into()), None);
        }

        // Verify event contains new IP
        let event = event_rx.recv().await.unwrap();
        // Removed print! to keep output clean
        match event {
            AppEvent::Disconnected {
                state: app_state,
                message: Some(_),
            } => {
                assert_eq!(
                    app_state.public_ip.unwrap().to_string(),
                    "203.0.113.20:8080"
                );
            }
            _ => panic!("Expected Disconnected event with updated IP"),
        }
    }

    /// Verifies that NAT type updates are broadcast correctly.
    #[tokio::test]
    async fn test_nat_type_update_broadcasts_event() {
        let state = create_test_state();
        let mut event_rx = state.read().await.subscribe_events();

        // Update NAT type
        {
            let mut guard = state.write().await;
            guard.set_nat_type(NatType::Cone, Some("NAT type detected".into()), None);
        }

        // Verify event
        let event = event_rx.recv().await.unwrap();
        match event {
            AppEvent::Disconnected {
                state: app_state,
                message: Some(_),
            } => {
                assert_eq!(app_state.nat_type, NatType::Cone);
            }
            _ => panic!("Expected Disconnected event"),
        }
    }

    #[tokio::test]
    async fn test_disconnect_when_disconnected_fails() {
        let state = create_test_state();
        let app = router(state.clone());

        let request = Request::builder()
            .method("POST")
            .uri("/api/disconnect")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_disconnect_when_connected_succeeds() {
        let state = create_test_state();

        // Set state to connected
        {
            state.write().await.status = Status::Connected;
        }

        let app = router(state.clone());

        let request = Request::builder()
            .method("POST")
            .uri("/api/disconnect")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_disconnect_when_punching_succeeds() {
        let state = create_test_state();

        // Set state to punching
        {
            state.write().await.status = Status::Punching;
        }

        let app = router(state.clone());

        let request = Request::builder()
            .method("POST")
            .uri("/api/disconnect")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
