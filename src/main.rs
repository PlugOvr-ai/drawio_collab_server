use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use axum::{
    extract::{
        ws::{Message as WsRawMessage, WebSocket, WebSocketUpgrade},
        Path as AxumPath, Query, State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response, Redirect},
    routing::{get, post, put, delete, get_service},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use dashmap::DashMap;
use futures::{sink::SinkExt, stream::StreamExt};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use tokio::{
    fs,
    io::AsyncWriteExt,
    sync::{broadcast, RwLock},
};
use tokio_stream::wrappers::BroadcastStream;
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};
use tracing::{error, info, Level};
use uuid::Uuid;
use clap::Parser;

#[derive(Clone)]
struct AppState {
    sessions: Arc<DashMap<String, String>>, // session_id -> username
    rooms: Arc<DashMap<String, Arc<Room>>>, // file_key -> room
    data_dir: Arc<PathBuf>,
    auth_token: String,
    require_token: bool,
}

struct Room {
    tx: broadcast::Sender<ServerWsMessage>,
    content: RwLock<String>,
    version: AtomicU64,
    members: DashMap<String, String>, // username -> color hex
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientWsMessage {
    Replace { version: u64, content: String },
    Ping,
    Cursor { x: f32, y: f32, basis: Option<String> }, // basis: "stage" or "overlay"
    Selection { ids: Vec<String> },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerWsMessage {
    Init { version: u64, content: String, your_id: String },
    Update { version: u64, content: String, username: String, sender_id: String },
    Error { message: String },
    Pong,
    PresenceSnapshot { users: Vec<PresenceUser> },
    PresenceJoin { username: String, color: String },
    PresenceLeave { username: String },
    Cursor { username: String, x: f32, y: f32, basis: Option<String>, sender_id: String },
    Selection { username: String, ids: Vec<String>, sender_id: String },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PresenceUser {
    username: String,
    color: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginResponse {
    username: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SetNameRequest {
    username: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileWriteRequest {
    content: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileContentResponse {
    name: String,
    version: u64,
    content: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileListItem {
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FsEntry {
    name: String,
    path: String,
    is_dir: bool,
    size: Option<u64>,
    modified_ms: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RenameRequest {
    new_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RenameBody {
    from: String,
    to: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct MkdirBody {
    path: String,
}

#[derive(Parser, Debug)]
#[command(name = "drawioserver")]
#[command(about = "Axum server for collaborative draw.io editing")]
struct Args {
    /// Require token for all file operations (like Jupyter). Also disables /login.
    #[arg(long, env = "DRAWIO_REQUIRE_TOKEN", default_value_t = false)]
    require_token: bool,

    /// Token value; if not provided, a random token is generated at startup
    #[arg(long, env = "DRAWIO_TOKEN")]
    token: Option<String>,

    /// Port to listen on
    #[arg(long, env = "PORT", default_value_t = 3000)]
    port: u16,

    /// Directory to store .drawio files
    #[arg(long, default_value = "data")]
    data_dir: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let args = Args::parse();

    let data_dir = args.data_dir.clone();
    if !data_dir.exists() {
        fs::create_dir_all(&data_dir).await?;
    }

    let auth_token = args.token.unwrap_or_else(|| Uuid::new_v4().to_string());
    let require_token = args.require_token;

    let state = AppState {
        sessions: Arc::new(DashMap::new()),
        rooms: Arc::new(DashMap::new()),
        data_dir: Arc::new(data_dir),
        auth_token,
        require_token,
    };

    let app = Router::new()
        .route("/", get(root_page))
        .route("/healthz", get(health))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/auth/token", get(token_login))
    .route("/me", get(me).put(put_me))
        .route("/files", get(list_files))
        .route("/files/:name", get(get_file).put(put_file).delete(delete_file))
        .route("/files/:name/rename", post(rename_file))
        // New query-based API for folders and downloads
        .route("/api/list", get(api_list))
        .route("/api/file", get(api_get_file).put(api_put_file).delete(api_delete_file))
        .route("/api/rename", post(api_rename))
        .route("/api/mkdir", post(api_mkdir))
        .route("/api/download", get(api_download))
        .route("/raw/:name", get(get_raw_file))
        .route("/ws/:name", get(ws_handler))
        .fallback_service(
            get_service(ServeDir::new("static")).handle_error(|_err| async move {
                (StatusCode::INTERNAL_SERVER_ERROR, "static file error")
            }),
        )
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::very_permissive(), // simplify testing; tighten for production
        )
        .with_state(state.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    info!("listening on http://{addr}");
    info!("require_token: {}", state.require_token);
    info!("token login: http://localhost:{}/auth/token?token={}", args.port, state.auth_token);
    info!("Set DRAWIO_TOKEN/--token to control the token. Current token: {}", state.auth_token);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn init_tracing() {
    let env_filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info,tower_http=info,axum=info".to_string());
    let _ = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_env_filter(env_filter)
        .with_target(false)
        .try_init();
}

async fn health() -> &'static str {
    "ok"
}

// ----- Auth helpers -----

async fn root_page(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if state.require_token {
        if get_authorized_user_from_header_or_query(&state, &headers, &q, &jar).is_none() {
            return Redirect::to("/token.html").into_response();
        }
    }
    // serve static index.html
    let bytes = match fs::read("static/index.html").await {
        Ok(b) => b,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let mut resp = Response::new(axum::body::Body::from(bytes));
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

fn get_session_user(state: &AppState, jar: &CookieJar) -> Option<String> {
    let sid = jar.get("sid")?.value().to_string();
    state.sessions.get(&sid).map(|e| e.value().clone())
}

fn get_authorized_user_from_header_or_query(
    state: &AppState,
    headers: &HeaderMap,
    query: &std::collections::HashMap<String, String>,
    jar: &CookieJar,
) -> Option<String> {
    // Session cookie
    if let Some(u) = get_session_user(state, jar) {
        return Some(u);
    }
    // Header: Authorization: token <TOKEN>
    if let Some(auth) = headers.get(axum::http::header::AUTHORIZATION).and_then(|h| h.to_str().ok()) {
        let prefix = "token ";
        if let Some(rest) = auth.strip_prefix(prefix) {
            if rest.trim() == state.auth_token {
                return Some("token".to_string());
            }
        }
    }
    // Query param ?token=...
    if let Some(t) = query.get("token") {
        if t == &state.auth_token {
            return Some("token".to_string());
        }
    }
    None
}

fn set_session_user<'a>(state: &AppState, mut jar: CookieJar, username: &str) -> CookieJar {
    let sid = Uuid::new_v4().to_string();
    state.sessions.insert(sid.clone(), username.to_string());
    let mut cookie = Cookie::new("sid", sid);
    cookie.set_path("/");
    cookie.set_http_only(true);
    // cookie.set_secure(true); // enable behind HTTPS
    jar.add(cookie)
}

fn clear_session<'a>(state: &AppState, mut jar: CookieJar) -> CookieJar {
    if let Some(cookie) = jar.get("sid") {
        let sid = cookie.value().to_string();
        state.sessions.remove(&sid);
        let mut c = Cookie::from(cookie.clone());
        c.set_value("");
        c.set_max_age(time::Duration::seconds(0));
        c.set_path("/");
        return jar.remove(c);
    }
    jar
}

// ----- Routes: Auth -----

async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    // Password login removed. Always disabled.
    (StatusCode::FORBIDDEN, "password login disabled; use token and PUT /me to set name").into_response()
}

async fn logout(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    let jar = clear_session(&state, jar);
    (jar, StatusCode::NO_CONTENT).into_response()
}

async fn me(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    if let Some(username) = get_session_user(&state, &jar) {
        Json(LoginResponse { username }).into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

async fn put_me(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
    Json(req): Json<SetNameRequest>,
) -> impl IntoResponse {
    // Require authorization via token or existing session
    if get_authorized_user_from_header_or_query(&state, &headers, &q, &jar).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let name = req.username.trim();
    if name.is_empty() || name.len() > 64 {
        return (StatusCode::BAD_REQUEST, "invalid name").into_response();
    }
    // If the caller already has a session, update it; otherwise create one
    if let Some(_existing) = get_session_user(&state, &jar) {
        // Update existing session by re-issuing cookie with new name
        let jar = set_session_user(&state, jar, name);
        (jar, Json(LoginResponse { username: name.to_string() })).into_response()
    } else {
        // No session cookie present (e.g., used Authorization header). Create one.
        let jar = set_session_user(&state, jar, name);
        (jar, Json(LoginResponse { username: name.to_string() })).into_response()
    }
}

// Token login like Jupyter's: /auth/token?token=...
async fn token_login(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(token) = params.get("token") {
        if token == &state.auth_token {
            let jar = set_session_user(&state, jar, "token");
            return (jar, Redirect::to("/")).into_response();
        }
    }
    StatusCode::UNAUTHORIZED.into_response()
}

// ----- File helpers -----

fn sanitize_name(name: &str) -> Option<String> {
    // Deny path traversal / directories
    if name.contains('/') || name.contains('\\') {
        return None;
    }
    // Only allow a conservative set of characters
    let valid = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' ));
    if !valid {
        return None;
    }
    Some(name.to_string())
}

fn sanitize_rel_path(path: &str) -> Option<String> {
    // allow forward slashes as separators; forbid backslashes
    if path.contains('\\') {
        return None;
    }
    let trimmed = path.trim_matches('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in trimmed.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return None;
        }
        let valid = part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ' | '(' | ')' | '+' | ',' ));
        if !valid {
            return None;
        }
        parts.push(part);
    }
    Some(parts.join("/"))
}

fn to_file_key(raw: &str) -> Option<String> {
    sanitize_name(raw)
}

fn to_data_path(data_dir: &Path, name: &str) -> PathBuf {
    data_dir.join(name)
}

fn to_data_rel_path(data_dir: &Path, rel: &str) -> PathBuf {
    let normalized = rel.trim_matches('/');
    data_dir.join(normalized)
}

async fn ensure_room_loaded(state: &AppState, file_key: &str) -> anyhow::Result<Arc<Room>> {
    if let Some(room) = state.rooms.get(file_key) {
        return Ok(room.value().clone());
    }
    let path = to_data_path(&state.data_dir, file_key);
    let content = if path.exists() {
        fs::read_to_string(&path).await.unwrap_or_default()
    } else {
        // Create an empty file for new documents
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).await.ok();
        }
        let mut f = fs::File::create(&path).await?;
        f.write_all(b"").await?;
        "".to_string()
    };

    // Initialize room
    let (tx, _rx) = broadcast::channel::<ServerWsMessage>(64);
    let room = Arc::new(Room {
        tx,
        content: RwLock::new(content),
        version: AtomicU64::new(0),
        members: DashMap::new(),
    });
    let inserted = state.rooms.insert(file_key.to_string(), room.clone());
    if inserted.is_some() {
        // another task inserted concurrently; use that one
        Ok(inserted.unwrap())
    } else {
        Ok(room)
    }
}

// ----- Routes: Files -----

async fn list_files(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if state.require_token {
        if get_authorized_user_from_header_or_query(&state, &headers, &q, &jar).is_none() {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    let mut items = Vec::<FileListItem>::new();
    let mut rd = match fs::read_dir(&*state.data_dir).await {
        Ok(rd) => rd,
        Err(_) => return Json(items).into_response(),
    };
    while let Ok(Some(e)) = rd.next_entry().await {
        if let Ok(ft) = e.file_type().await {
            if ft.is_file() {
                if let Some(name) = e.file_name().to_str() {
                    if name.ends_with(".drawio") {
                        items.push(FileListItem {
                            name: name.to_string(),
                        });
                    }
                }
            }
        }
    }
    Json(items).into_response()
}

async fn get_file(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    if state.require_token {
        if get_authorized_user_from_header_or_query(&state, &headers, &q, &jar).is_none() {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    let decoded = percent_decode_str(&name).decode_utf8_lossy().to_string();
    let Some(file_key) = to_file_key(&decoded) else {
        return (StatusCode::BAD_REQUEST, "invalid file name").into_response();
    };
    match ensure_room_loaded(&state, &file_key).await {
        Ok(room) => {
            let content = room.content.read().await.clone();
            let version = room.version.load(Ordering::SeqCst);
            Json(FileContentResponse {
                name: file_key,
                version,
                content,
            })
            .into_response()
        }
        Err(err) => {
            error!("get_file error: {err:?}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn put_file(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
    AxumPath(name): AxumPath<String>,
    Json(req): Json<FileWriteRequest>,
) -> impl IntoResponse {
    let Some(_username) = get_authorized_user_from_header_or_query(&state, &headers, &q, &jar) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    let decoded = percent_decode_str(&name).decode_utf8_lossy().to_string();
    let Some(file_key) = to_file_key(&decoded) else {
        return (StatusCode::BAD_REQUEST, "invalid file name").into_response();
    };
    match ensure_room_loaded(&state, &file_key).await {
        Ok(room) => {
            {
                let mut guard = room.content.write().await;
                *guard = req.content.clone();
                let _new_ver = room.version.fetch_add(1, Ordering::SeqCst) + 1;
            }
            let path = to_data_path(&state.data_dir, &file_key);
            if let Err(err) = fs::write(&path, req.content.as_bytes()).await {
                error!("write file error: {err:?}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(err) => {
            error!("put_file error: {err:?}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn delete_file(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    let Some(_username) = get_authorized_user_from_header_or_query(&state, &headers, &q, &jar) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let decoded = percent_decode_str(&name).decode_utf8_lossy().to_string();
    let Some(file_key) = to_file_key(&decoded) else {
        return (StatusCode::BAD_REQUEST, "invalid file name").into_response();
    };
    let path = to_data_path(&state.data_dir, &file_key);
    if let Err(err) = fs::remove_file(&path).await {
        error!("delete file error: {err:?}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    state.rooms.remove(&file_key);
    StatusCode::NO_CONTENT.into_response()
}

async fn rename_file(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
    AxumPath(name): AxumPath<String>,
    Json(req): Json<RenameRequest>,
) -> impl IntoResponse {
    let Some(_username) = get_authorized_user_from_header_or_query(&state, &headers, &q, &jar) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let decoded_old = percent_decode_str(&name).decode_utf8_lossy().to_string();
    let Some(old_key) = to_file_key(&decoded_old) else {
        return (StatusCode::BAD_REQUEST, "invalid old file name").into_response();
    };
    let Some(new_key) = to_file_key(&req.new_name) else {
        return (StatusCode::BAD_REQUEST, "invalid new file name").into_response();
    };
    if !new_key.ends_with(".drawio") {
        return (StatusCode::BAD_REQUEST, "new name must end with .drawio").into_response();
    }
    let old_path = to_data_path(&state.data_dir, &old_key);
    let new_path = to_data_path(&state.data_dir, &new_key);
    if let Err(err) = fs::rename(&old_path, &new_path).await {
        error!("rename file error: {err:?}");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if let Some((_k, room)) = state.rooms.remove(&old_key) {
        state.rooms.insert(new_key.clone(), room);
    }
    Json(serde_json::json!({ "name": new_key })).into_response()
}

// ----- Routes: WebSocket -----

async fn get_raw_file(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    if state.require_token {
        if get_authorized_user_from_header_or_query(&state, &headers, &q, &jar).is_none() {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    let decoded = percent_decode_str(&name).decode_utf8_lossy().to_string();
    let Some(file_key) = to_file_key(&decoded) else {
        return (StatusCode::BAD_REQUEST, "invalid file name").into_response();
    };
    match ensure_room_loaded(&state, &file_key).await {
        Ok(room) => {
            let content = room.content.read().await.clone();
            let mut resp = Response::new(axum::body::Body::from(content));
            let headers = resp.headers_mut();
            headers.insert(axum::http::header::CONTENT_TYPE, axum::http::HeaderValue::from_static("application/xml; charset=utf-8"));
            headers.insert(axum::http::header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
            resp
        }
        Err(err) => {
            error!("get_raw_file error: {err:?}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn ws_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    AxumPath(name): AxumPath<String>,
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let Some(username) = get_authorized_user_from_header_or_query(&state, &headers, &q, &jar) else {
        return (StatusCode::UNAUTHORIZED, "login required").into_response();
    };
    // Prefer path from query (?path=...) to support folders; fallback to :name
    let file_key = if let Some(p) = q.get("path") {
        if let Some(safe) = sanitize_rel_path(p) { safe } else { return (StatusCode::BAD_REQUEST, "invalid path").into_response() }
    } else {
        let decoded = percent_decode_str(&name).decode_utf8_lossy().to_string();
        let Some(file_key) = to_file_key(&decoded) else {
            return (StatusCode::BAD_REQUEST, "invalid file name").into_response();
        };
        file_key
    };
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("-");
    info!("ws connect: user={username} file={file_key} ua={user_agent}");
    ws.on_upgrade(move |socket| handle_ws(socket, state, username, file_key))
}

fn color_for_username(username: &str) -> String {
    // Deterministic color from username: simple hash to HSL then convert to hex (approximate with fixed saturation/lightness)
    let mut hash = 0u32;
    for b in username.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(b as u32);
    }
    let hue = (hash % 360) as f32;
    let (s, l) = (0.65f32, 0.55f32);
    hsl_to_hex(hue, s, l)
}

fn hsl_to_hex(h: f32, s: f32, l: f32) -> String {
    // Convert HSL to RGB then hex; simple implementation
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let x = c * (1.0 - (((h / 60.0) % 2.0) - 1.0).abs());
    let m = l - c / 2.0;
    let (r1, g1, b1) = if (0.0..60.0).contains(&h) {
        (c, x, 0.0)
    } else if (60.0..120.0).contains(&h) {
        (x, c, 0.0)
    } else if (120.0..180.0).contains(&h) {
        (0.0, c, x)
    } else if (180.0..240.0).contains(&h) {
        (0.0, x, c)
    } else if (240.0..300.0).contains(&h) {
        (x, 0.0, c)
    } else {
        (c, 0.0, x)
    };
    let (r, g, b) = (
        ((r1 + m) * 255.0).round() as u8,
        ((g1 + m) * 255.0).round() as u8,
        ((b1 + m) * 255.0).round() as u8,
    );
    format!("#{:02x}{:02x}{:02x}", r, g, b)
}

async fn handle_ws(mut socket: WebSocket, state: AppState, username: String, file_key: String) {
    let Ok(room) = ensure_room_loaded(&state, &file_key).await else {
        let _ = socket
            .send(WsRawMessage::Text(
                serde_json::to_string(&ServerWsMessage::Error {
                    message: "failed to load file".to_string(),
                })
                .unwrap(),
            ))
            .await;
        let _ = socket.close().await;
        return;
    };

    // subscribe to room broadcast
    let mut rx = room.tx.subscribe();
    // unique id for this connection
    let conn_id = Uuid::new_v4().to_string();

    // send init snapshot
    {
        let content = room.content.read().await.clone();
        let version = room.version.load(std::sync::atomic::Ordering::SeqCst);
        let init_msg = ServerWsMessage::Init { version, content, your_id: conn_id.clone() };
        let _ = socket
            .send(WsRawMessage::Text(serde_json::to_string(&init_msg).unwrap()))
            .await;
    }

    // send presence snapshot and announce join
    {
        // record member with color
        let color = color_for_username(&username);
        room.members.insert(username.clone(), color.clone());
        let snapshot = room
            .members
            .iter()
            .filter(|e| e.key() != &username)
            .map(|e| PresenceUser {
                username: e.key().clone(),
                color: e.value().clone(),
            })
            .collect::<Vec<_>>();
        let _ = socket
            .send(WsRawMessage::Text(
                serde_json::to_string(&ServerWsMessage::PresenceSnapshot { users: snapshot }).unwrap(),
            ))
            .await;
        let _ = room.tx.send(ServerWsMessage::PresenceJoin {
            username: username.clone(),
            color,
        });
    }

    let (mut sender, mut receiver) = socket.split();

    // Merge room broadcast and incoming client messages into one loop to use a single sender
    let mut room_stream = BroadcastStream::new(rx);

    loop {
        tokio::select! {
            maybe_incoming = receiver.next() => {
                let Some(Ok(incoming)) = maybe_incoming else { break; };
                match incoming {
                    WsRawMessage::Text(txt) => {
                        match serde_json::from_str::<ClientWsMessage>(&txt) {
                            Ok(ClientWsMessage::Replace { version: _version, content }) => {
                                // naive versioning: accept any update, bump version, save to disk, broadcast
                                {
                                    let mut guard = room.content.write().await;
                                    *guard = content.clone();
                                    room.version.fetch_add(1, Ordering::SeqCst);
                                }
                                let new_version = room.version.load(Ordering::SeqCst);
                                // persist
                                let path = to_data_path(&state.data_dir, &file_key);
                                if let Err(err) = fs::write(&path, content.as_bytes()).await {
                                    error!("ws write file error: {err:?}");
                                }
                                let _ = room.tx.send(ServerWsMessage::Update {
                                    version: new_version,
                                    content,
                                    username: username.clone(),
                                    sender_id: conn_id.clone(),
                                });
                            }
                            Ok(ClientWsMessage::Cursor { x, y, basis }) => {
                                let x = x.clamp(0.0, 1.0);
                                let y = y.clamp(0.0, 1.0);
                                let _ = room.tx.send(ServerWsMessage::Cursor {
                                    username: username.clone(),
                                    x, y,
                                    basis,
                                    sender_id: conn_id.clone(),
                                });
                            }
                            Ok(ClientWsMessage::Ping) => {
                                let _ = sender
                                    .send(WsRawMessage::Text(
                                        serde_json::to_string(&ServerWsMessage::Pong).unwrap(),
                                    ))
                                    .await;
                            }
                            Ok(ClientWsMessage::Selection { ids }) => {
                                let _ = room.tx.send(ServerWsMessage::Selection {
                                    username: username.clone(),
                                    ids,
                                    sender_id: conn_id.clone(),
                                });
                            }
                            Err(err) => {
                                let _ = sender
                                    .send(WsRawMessage::Text(
                                        serde_json::to_string(&ServerWsMessage::Error {
                                            message: format!("invalid message: {err}"),
                                        })
                                        .unwrap(),
                                    ))
                                    .await;
                            }
                        }
                    }
                    WsRawMessage::Close(_f) => {
                        break;
                    }
                    WsRawMessage::Ping(data) => {
                        let _ = sender.send(WsRawMessage::Pong(data)).await;
                    }
                    _ => {}
                }
            }
            maybe_room_msg = room_stream.next() => {
                match maybe_room_msg {
                    Some(Ok(msg)) => {
                        if sender
                            .send(WsRawMessage::Text(
                                serde_json::to_string(&msg).unwrap_or_else(|_| "{\"type\":\"error\",\"message\":\"encode\"}".to_string()),
                            ))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Some(Err(_e)) => {
                        // lagging receiver; skip
                    }
                    None => {
                        // broadcast channel closed
                        break;
                    }
                }
            }
        }
    }

    // on disconnect: announce leave
    room.members.remove(&username);
    let _ = room.tx.send(ServerWsMessage::PresenceLeave { username });
}

// ----- New Folder-capable API -----

async fn api_list(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if state.require_token {
        if get_authorized_user_from_header_or_query(&state, &headers, &q, &jar).is_none() {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    let rel = q.get("path").cloned().unwrap_or_else(|| "".to_string());
    let Some(safe) = sanitize_rel_path(&rel).or_else(|| if rel.is_empty() { Some("".to_string()) } else { None }) else {
        return (StatusCode::BAD_REQUEST, "invalid path").into_response();
    };
    let dir_path = to_data_rel_path(&state.data_dir, &safe);
    let mut out: Vec<FsEntry> = Vec::new();
    let mut rd = match fs::read_dir(&dir_path).await {
        Ok(rd) => rd,
        Err(_) => return Json(out).into_response(),
    };
    while let Ok(Some(ent)) = rd.next_entry().await {
        let name = ent.file_name().to_string_lossy().to_string();
        let meta = match ent.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        let mut size = None;
        let mut modified_ms = None;
        if meta.is_file() {
            size = Some(meta.len());
        }
        if let Ok(m) = meta.modified() {
            if let Ok(dur) = m.duration_since(std::time::UNIX_EPOCH) {
                modified_ms = Some(dur.as_millis() as i64);
            }
        }
        if meta.is_dir() {
            out.push(FsEntry {
                name: name.clone(),
                path: if safe.is_empty() { name.clone() } else { format!("{}/{}", safe, name) },
                is_dir: true,
                size: None,
                modified_ms,
            });
        } else if meta.is_file() {
            if name.ends_with(".drawio") {
                out.push(FsEntry {
                    name: name.clone(),
                    path: if safe.is_empty() { name.clone() } else { format!("{}/{}", safe, name) },
                    is_dir: false,
                    size,
                    modified_ms,
                });
            }
        } else {
            // symlink or other: try to resolve to target type
            if let Ok(ft) = ent.file_type().await {
                if ft.is_symlink() {
                    // attempt read_link -> metadata
                    if let Ok(target_meta) = tokio::fs::metadata(ent.path()).await {
                        if target_meta.is_dir() {
                            out.push(FsEntry {
                                name: name.clone(),
                                path: if safe.is_empty() { name.clone() } else { format!("{}/{}", safe, name) },
                                is_dir: true,
                                size: None,
                                modified_ms,
                            });
                        } else if target_meta.is_file() && name.ends_with(".drawio") {
                            out.push(FsEntry {
                                name: name.clone(),
                                path: if safe.is_empty() { name.clone() } else { format!("{}/{}", safe, name) },
                                is_dir: false,
                                size,
                                modified_ms,
                            });
                        }
                    }
                }
            }
        }
    }
    out.sort_by(|a, b| a.is_dir.cmp(&b.is_dir).reverse().then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    Json(out).into_response()
}

async fn api_get_file(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let Some(_u) = get_authorized_user_from_header_or_query(&state, &headers, &q, &jar) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(path) = q.get("path") else { return (StatusCode::BAD_REQUEST, "missing path").into_response() };
    let Some(safe) = sanitize_rel_path(path) else { return (StatusCode::BAD_REQUEST, "invalid path").into_response() };
    match ensure_room_loaded(&state, &safe).await {
        Ok(room) => {
            let content = room.content.read().await.clone();
            let version = room.version.load(Ordering::SeqCst);
            Json(FileContentResponse { name: safe, version, content }).into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn api_put_file(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
    Json(req): Json<FileWriteRequest>,
) -> impl IntoResponse {
    let Some(_u) = get_authorized_user_from_header_or_query(&state, &headers, &q, &jar) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(path) = q.get("path") else { return (StatusCode::BAD_REQUEST, "missing path").into_response() };
    let Some(safe) = sanitize_rel_path(path) else { return (StatusCode::BAD_REQUEST, "invalid path").into_response() };
    let pb = to_data_rel_path(&state.data_dir, &safe);
    if let Some(parent) = pb.parent() {
        let _ = fs::create_dir_all(parent).await;
    }
    let room = ensure_room_loaded(&state, &safe).await.map_err(|_| ()).ok();
    if let Some(room) = room {
        {
            let mut guard = room.content.write().await;
            *guard = req.content.clone();
            room.version.fetch_add(1, Ordering::SeqCst);
        }
    }
    if let Err(_) = fs::write(&pb, req.content.as_bytes()).await {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn api_delete_file(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let Some(_u) = get_authorized_user_from_header_or_query(&state, &headers, &q, &jar) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(path) = q.get("path") else { return (StatusCode::BAD_REQUEST, "missing path").into_response() };
    let Some(safe) = sanitize_rel_path(path) else { return (StatusCode::BAD_REQUEST, "invalid path").into_response() };
    let pb = to_data_rel_path(&state.data_dir, &safe);
    if let Err(_) = fs::remove_file(&pb).await {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    state.rooms.remove(&safe);
    StatusCode::NO_CONTENT.into_response()
}

async fn api_rename(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
    Json(body): Json<RenameBody>,
) -> impl IntoResponse {
    let Some(_u) = get_authorized_user_from_header_or_query(&state, &headers, &q, &jar) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(from) = sanitize_rel_path(&body.from) else { return (StatusCode::BAD_REQUEST, "invalid from").into_response() };
    let Some(to) = sanitize_rel_path(&body.to) else { return (StatusCode::BAD_REQUEST, "invalid to").into_response() };
    if !to.ends_with(".drawio") {
        return (StatusCode::BAD_REQUEST, "new name must end with .drawio").into_response();
    }
    let from_pb = to_data_rel_path(&state.data_dir, &from);
    let to_pb = to_data_rel_path(&state.data_dir, &to);
    if let Some(parent) = to_pb.parent() {
        let _ = fs::create_dir_all(parent).await;
    }
    if let Err(_) = fs::rename(&from_pb, &to_pb).await {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if let Some((_k, room)) = state.rooms.remove(&from) {
        state.rooms.insert(to.clone(), room);
    }
    Json(serde_json::json!({ "path": to })).into_response()
}

async fn api_mkdir(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
    Json(body): Json<MkdirBody>,
) -> impl IntoResponse {
    let Some(_u) = get_authorized_user_from_header_or_query(&state, &headers, &q, &jar) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(safe) = sanitize_rel_path(&body.path) else { return (StatusCode::BAD_REQUEST, "invalid path").into_response() };
    let pb = to_data_rel_path(&state.data_dir, &safe);
    if let Err(_) = fs::create_dir_all(&pb).await {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn api_download(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let Some(_u) = get_authorized_user_from_header_or_query(&state, &headers, &q, &jar) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(path) = q.get("path") else { return (StatusCode::BAD_REQUEST, "missing path").into_response() };
    let Some(safe) = sanitize_rel_path(path) else { return (StatusCode::BAD_REQUEST, "invalid path").into_response() };
    let pb = to_data_rel_path(&state.data_dir, &safe);
    let Ok(bytes) = fs::read(&pb).await else { return StatusCode::NOT_FOUND.into_response() };
    let mut resp = Response::new(axum::body::Body::from(bytes));
    resp.headers_mut().insert(axum::http::header::CONTENT_TYPE, axum::http::HeaderValue::from_static("application/xml"));
    let filename = safe.split('/').last().unwrap_or("diagram.drawio");
    let cd = format!("attachment; filename=\"{}\"", filename);
    if let Ok(val) = axum::http::HeaderValue::from_str(&cd) {
        resp.headers_mut().insert(axum::http::header::CONTENT_DISPOSITION, val);
    }
    resp
}

