use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use axum::{
    extract::{State, Query},
    routing::{get, post},
    Router, Json, response::{Html, IntoResponse},
    http::header,
};

use serde_json::{Value, json};
use crate::database::{DatabaseManager, Disposition, MessageRecord, HistoryFilterParams};
use crate::config::{WebServerConfig, TrackingConfig};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct CommandServerManager {
    config_server: Option<WebServerConfig>,
    tracking_config: Option<TrackingConfig>,
    configured_interfaces: Vec<String>,

    pub stats_total: u64,
    pub stats_forwarded: u64,
    pub stats_partially_forwarded: u64,
    pub stats_dropped: u64,

    pub db_manager: Option<DatabaseManager>,
    db_buffer_messages: Vec<MessageRecord>,
    last_flush_time: f64,
}

impl CommandServerManager {
    pub fn new(
        config_server: Option<WebServerConfig>,
        tracking_config: Option<TrackingConfig>,
        configured_interfaces: Vec<String>,
    ) -> Self {
        let mut db_manager = None;
        let mut stats_total = 0;
        let mut stats_forwarded = 0;
        let mut stats_partially_forwarded = 0;
        let mut stats_dropped = 0;

        if let Some(ref tc) = tracking_config {
            if tc.enabled {
                let db = DatabaseManager::new(&tc.db_path);
                let (t, f, pf, d) = db.load_global_stats();
                stats_total = t;
                stats_forwarded = f;
                stats_partially_forwarded = pf;
                stats_dropped = d;
                db_manager = Some(db);
            }
        }

        Self {
            config_server,
            tracking_config,
            configured_interfaces,
            stats_total,
            stats_forwarded,
            stats_partially_forwarded,
            stats_dropped,
            db_manager,
            db_buffer_messages: Vec::new(),
            last_flush_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64(),
        }
    }

    pub fn record_message(&mut self, record: MessageRecord) {
        let web_enabled = self.config_server.as_ref().map(|c| c.enabled).unwrap_or(false);
        let tracking_enabled = self.tracking_config.as_ref().map(|c| c.enabled).unwrap_or(false);

        if web_enabled || tracking_enabled {
            self.stats_total += 1;
            if record.disposition == Disposition::Forwarded as u8 {
                self.stats_forwarded += 1;
            } else if record.disposition == Disposition::PartiallyForwarded as u8 {
                self.stats_partially_forwarded += 1;
            } else {
                self.stats_dropped += 1;
            }
        }

        if tracking_enabled && self.db_manager.is_some() {
            self.db_buffer_messages.push(record);
            let force_flush = self.db_buffer_messages.len() >= 200;
            self.flush_stats(force_flush);
        }
    }

    pub fn flush_messages_buffer(&mut self) {
        if let Some(db) = &self.db_manager {
            if !self.db_buffer_messages.is_empty() {
                db.batch_insert_messages(&self.db_buffer_messages);
                self.db_buffer_messages.clear();
            }
            db.save_global_stats(
                self.stats_total,
                self.stats_forwarded,
                self.stats_partially_forwarded,
                self.stats_dropped,
            );
        }
    }

    pub fn flush_stats(&mut self, force: bool) {
        let (retention_days, max_records, flush_interval) = match &self.tracking_config {
            Some(c) if c.enabled => (c.effective_retention_days(), c.effective_max_records(), c.flush_interval_seconds),
            _ => return,
        };
        if self.db_manager.is_none() {
            return;
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
        if !force && (now - self.last_flush_time) < (flush_interval as f64) {
            return;
        }
        self.last_flush_time = now;

        self.flush_messages_buffer();

        if let Some(db) = &self.db_manager {
            db.prune_old_records(retention_days, max_records);
        }
    }

    pub fn process_command(&mut self, payload: &Value) -> Value {
        let cmd = match payload.get("command").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => return json!({"status": "error", "error": "Missing 'command' key"}),
        };

        match cmd {
            "stats" => {
                json!({
                    "status": "ok",
                    "data": {
                        "total": self.stats_total,
                        "forwarded": self.stats_forwarded,
                        "partially_forwarded": self.stats_partially_forwarded,
                        "dropped": self.stats_dropped,
                    },
                    "interfaces": self.configured_interfaces,
                    "version": "0.1.0",
                    "commit": "rust-port"
                })
            }
            "clear" => {
                self.stats_total = 0;
                self.stats_forwarded = 0;
                self.stats_partially_forwarded = 0;
                self.stats_dropped = 0;
                if let Some(db) = &self.db_manager {
                    db.save_global_stats(0, 0, 0, 0);
                    if payload.get("clear_tracking").and_then(|v| v.as_bool()).unwrap_or(false) {
                        self.db_buffer_messages.clear();
                        db.clear_tracking_data();
                    }
                }
                json!({"status": "ok"})
            }
            _ => json!({"status": "error", "error": "Unknown command"}),
        }
    }
}

pub async fn run_command_server(manager: Arc<Mutex<CommandServerManager>>, host: String, port: u16) {
    let app = Router::new()
        .route("/", get(serve_index))
        .route("/index.html", get(serve_index))
        .route("/app.js", get(serve_app_js))
        .route("/style.css", get(serve_style_css))
        .route("/favicon.svg", get(serve_favicon))
        .route("/api/stats", get(api_stats))
        .route("/api/history", get(api_history))
        .route("/api/clear", post(api_clear))
        .with_state(manager);

    let addr = format!("{}:{}", host, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind Web Server: {}", e);
            return;
        }
    };
    
    println!("Web GUI listening on http://{}", addr);
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("Web server error: {}", e);
    }
}

async fn serve_index() -> impl IntoResponse {
    Html(include_str!("../static/index.html"))
}

async fn serve_app_js() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/javascript")], include_str!("../static/app.js"))
}

async fn serve_style_css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css")], include_str!("../static/style.css"))
}

async fn serve_favicon() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/svg+xml")], include_str!("../static/favicon.svg"))
}

async fn api_stats(State(manager): State<Arc<Mutex<CommandServerManager>>>) -> Json<Value> {
    let mut mgr = manager.lock().await;
    Json(mgr.process_command(&json!({"command": "stats"})))
}

#[derive(serde::Deserialize)]
pub struct ClearCommandBody {
    #[serde(default)]
    clear_tracking: bool,
}

async fn api_clear(
    State(manager): State<Arc<Mutex<CommandServerManager>>>,
    axum::extract::Json(body): axum::extract::Json<ClearCommandBody>,
) -> Json<Value> {
    let mut mgr = manager.lock().await;
    Json(mgr.process_command(&json!({"command": "clear", "clear_tracking": body.clear_tracking})))
}

#[derive(serde::Deserialize)]
pub struct HistoryQueryRequest {
    pub page: Option<usize>,
    pub limit: Option<usize>,
    pub src_ip: Option<String>,
    pub src_interface: Option<String>,
    pub dst_interface: Option<String>,
    pub disposition: Option<u8>,
    pub packet_type: Option<u8>,
    pub query_search: Option<String>,
    pub response_search: Option<String>,
    pub from_time: Option<f64>,
    pub to_time: Option<f64>,
}

async fn api_history(
    State(manager): State<Arc<Mutex<CommandServerManager>>>,
    Query(query): Query<HistoryQueryRequest>,
) -> Json<Value> {
    let mut mgr = manager.lock().await;
    mgr.flush_messages_buffer();

    let interfaces = mgr.configured_interfaces.clone();

    if let Some(db) = &mgr.db_manager {
        let filters = HistoryFilterParams {
            page: query.page,
            limit: query.limit,
            src_ip: query.src_ip,
            src_interface: query.src_interface,
            dst_interface: query.dst_interface,
            disposition: query.disposition,
            packet_type: query.packet_type,
            query_search: query.query_search,
            response_search: query.response_search,
            from_time: query.from_time,
            to_time: query.to_time,
        };
        let page = filters.page.unwrap_or(1).max(1);
        let limit = filters.limit.unwrap_or(50).clamp(1, 200);
        let (records, total) = db.query_messages(&filters);
        let total_pages = if total == 0 { 1 } else { (total + limit - 1) / limit };

        Json(json!({
            "status": "ok",
            "data": {
                "records": records,
                "total": total,
                "page": page,
                "limit": limit,
                "total_pages": total_pages,
                "interfaces": interfaces,
            }
        }))
    } else {
        Json(json!({
            "status": "error",
            "error": "Database tracking is disabled"
        }))
    }
}
