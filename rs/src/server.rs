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
use crate::config::{
    AppConfig, AppConfigData, WebServerConfig, TrackingConfig, discover_system_interfaces,
};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct FlushTask {
    db: DatabaseManager,
    messages: Vec<MessageRecord>,
    stats: (u64, u64, u64, u64),
    prune_params: Option<(u32, usize)>,
}

impl FlushTask {
    pub fn execute(self) {
        if !self.messages.is_empty() {
            self.db.batch_insert_messages(&self.messages);
        }
        let (total, forwarded, partially_forwarded, dropped) = self.stats;
        self.db.save_global_stats(total, forwarded, partially_forwarded, dropped);
        if let Some((retention_days, max_records)) = self.prune_params {
            self.db.prune_old_records(retention_days, max_records);
        }
    }
}

pub struct CommandServerManager {
    config_server: Option<WebServerConfig>,
    bound_web_server: Option<WebServerConfig>,
    tracking_config: Option<TrackingConfig>,
    configured_interfaces: Vec<String>,
    config_path: Option<String>,
    config_data: Option<AppConfigData>,
    config_tx: Option<tokio::sync::watch::Sender<Arc<AppConfig>>>,

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
            bound_web_server: config_server.clone(),
            config_server,
            tracking_config,
            configured_interfaces,
            config_path: None,
            config_data: None,
            config_tx: None,
            stats_total,
            stats_forwarded,
            stats_partially_forwarded,
            stats_dropped,
            db_manager,
            db_buffer_messages: Vec::new(),
            last_flush_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64(),
        }
    }

    pub fn set_config_context(
        &mut self,
        config_path: String,
        config_data: AppConfigData,
        config_tx: tokio::sync::watch::Sender<Arc<AppConfig>>,
    ) {
        self.config_path = Some(config_path);
        self.config_data = Some(config_data);
        self.config_tx = Some(config_tx);
    }

    pub fn is_restart_required(&self) -> bool {
        match (&self.bound_web_server, &self.config_server) {
            (Some(bound), Some(current)) => bound.host != current.host || bound.port != current.port,
            _ => false,
        }
    }

    pub fn current_config_data(&self) -> AppConfigData {
        if let Some(ref data) = self.config_data {
            data.clone()
        } else {
            AppConfigData {
                interfaces: self.configured_interfaces.clone(),
                default_action: "forward".to_string(),
                rewrite_mixed_packets: false,
                forward_known_answers: false,
                web_server: self.config_server.clone(),
                tracking: self.tracking_config.clone(),
                rules: Vec::new(),
                ssdp: None,
            }
        }
    }

    pub fn apply_updated_config(
        &mut self,
        mut new_data: AppConfigData,
    ) -> Result<(AppConfigData, String, bool), String> {
        // Prevent locking out the Web GUI by ensuring web_server remains enabled
        match new_data.web_server {
            Some(ref mut ws) => {
                ws.enabled = true;
            }
            None => {
                if let Some(ref existing_ws) = self.config_server {
                    let mut ws = existing_ws.clone();
                    ws.enabled = true;
                    new_data.web_server = Some(ws);
                } else {
                    new_data.web_server = Some(WebServerConfig {
                        enabled: true,
                        host: "0.0.0.0".to_string(),
                        port: 8080,
                    });
                }
            }
        }

        new_data.normalize();
        new_data.validate()?;

        let yaml_str = if let Some(ref path) = self.config_path {
            new_data.save_to_file(path)?
        } else {
            new_data.to_commented_yaml()?
        };

        // Flush existing buffer before reconfiguring database tracking
        self.flush_stats(true);

        let old_db_path = self.tracking_config.as_ref().map(|tc| tc.db_path.as_str());
        match &new_data.tracking {
            Some(tc) if tc.enabled => {
                let need_new_db = self.db_manager.is_none() || old_db_path != Some(tc.db_path.as_str());
                if need_new_db {
                    let db = DatabaseManager::new(&tc.db_path);
                    self.db_manager = Some(db);
                }
            }
            _ => {
                self.db_manager = None;
                self.db_buffer_messages.clear();
            }
        }

        self.tracking_config = new_data.tracking.clone();
        self.configured_interfaces = new_data.interfaces.clone();
        self.config_server = new_data.web_server.clone();
        self.config_data = Some(new_data.clone());

        if let Some(ref tx) = self.config_tx {
            let new_app_cfg = Arc::new(AppConfig::from_data(&new_data));
            let _ = tx.send(new_app_cfg);
        }

        // Trigger immediate prune if tracking is enabled with new limits
        self.flush_stats(true);

        let restart_required = self.is_restart_required();
        Ok((new_data, yaml_str, restart_required))
    }

    pub fn record_message_deferred(&mut self, record: MessageRecord) -> Option<FlushTask> {
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
            return self.prepare_flush_task(force_flush, true);
        }
        None
    }

    pub fn prepare_flush_task(&mut self, force: bool, include_prune: bool) -> Option<FlushTask> {
        let (retention_days, max_records, flush_interval) = match &self.tracking_config {
            Some(c) if c.enabled => (c.effective_retention_days(), c.effective_max_records(), c.flush_interval_seconds),
            _ => return None,
        };
        let db = self.db_manager.as_ref()?.clone();

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
        if !force && (now - self.last_flush_time) < (flush_interval as f64) {
            return None;
        }
        self.last_flush_time = now;

        let messages = std::mem::take(&mut self.db_buffer_messages);
        let stats = (
            self.stats_total,
            self.stats_forwarded,
            self.stats_partially_forwarded,
            self.stats_dropped,
        );
        let prune_params = if include_prune {
            Some((retention_days, max_records))
        } else {
            None
        };

        Some(FlushTask {
            db,
            messages,
            stats,
            prune_params,
        })
    }

    pub fn flush_stats(&mut self, force: bool) {
        if let Some(task) = self.prepare_flush_task(force, true) {
            task.execute();
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
                let clear_tracking = payload.get("clear_tracking").and_then(|v| v.as_bool()).unwrap_or(false);
                if clear_tracking {
                    self.db_buffer_messages.clear();
                }
                if let Some(db) = &self.db_manager {
                    db.save_global_stats(0, 0, 0, 0);
                    if clear_tracking {
                        db.clear_tracking_data();
                    }
                }
                json!({"status": "ok"})
            }
            _ => json!({"status": "error", "error": "Unknown command"}),
        }
    }
}

pub fn build_router(manager: Arc<Mutex<CommandServerManager>>) -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/index.html", get(serve_index))
        .route("/app.js", get(serve_app_js))
        .route("/style.css", get(serve_style_css))
        .route("/favicon.svg", get(serve_favicon))
        .route("/api/stats", get(api_stats))
        .route("/api/history", get(api_history))
        .route("/api/ssdp/history", get(api_ssdp_history))
        .route("/api/clear", post(api_clear))
        .route("/api/config", get(api_get_config).post(api_save_config))
        .route("/api/interfaces", get(api_get_interfaces))
        .with_state(manager)
}

pub async fn run_command_server(manager: Arc<Mutex<CommandServerManager>>, host: String, port: u16) {
    let app = build_router(manager);

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

#[derive(serde::Deserialize)]
struct SsdpHistoryQuery {
    page: Option<usize>,
    limit: Option<usize>,
}

async fn api_ssdp_history(
    State(mgr): State<Arc<Mutex<CommandServerManager>>>,
    Query(params): Query<SsdpHistoryQuery>,
) -> impl IntoResponse {
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(50).clamp(1, 500);
    let mgr_guard = mgr.lock().await;
    if let Some(ref db) = mgr_guard.db_manager {
        let (items, total) = db.get_ssdp_history(page, limit);
        return Json(serde_json::json!({
            "items": items,
            "total": total,
            "page": page,
            "limit": limit
        })).into_response();
    }
    Json(serde_json::json!({
        "items": [],
        "total": 0,
        "page": page,
        "limit": limit
    })).into_response()
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
    let clear_tracking = body.clear_tracking;
    let db_opt = {
        let mut mgr = manager.lock().await;
        mgr.stats_total = 0;
        mgr.stats_forwarded = 0;
        mgr.stats_partially_forwarded = 0;
        mgr.stats_dropped = 0;
        if clear_tracking {
            mgr.db_buffer_messages.clear();
        }
        mgr.db_manager.clone()
    };

    if let Some(db) = db_opt {
        let _ = tokio::task::spawn_blocking(move || {
            db.save_global_stats(0, 0, 0, 0);
            if clear_tracking {
                db.clear_tracking_data();
            }
        }).await;
    }

    Json(json!({"status": "ok"}))
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
    let (db_opt, flush_task, interfaces) = {
        let mut mgr = manager.lock().await;
        let flush_task = mgr.prepare_flush_task(true, false);
        (mgr.db_manager.clone(), flush_task, mgr.configured_interfaces.clone())
    };

    if let Some(db) = db_opt {
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

        let query_res = tokio::task::spawn_blocking(move || {
            if let Some(task) = flush_task {
                task.execute();
            }
            db.query_messages(&filters)
        }).await;

        let (records, total) = query_res.unwrap_or_else(|_| (Vec::new(), 0));
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

async fn api_get_config(State(manager): State<Arc<Mutex<CommandServerManager>>>) -> Json<Value> {
    let mgr = manager.lock().await;
    let cfg_data = mgr.current_config_data();
    let yaml = cfg_data.to_commented_yaml().unwrap_or_default();
    let restart_required = mgr.is_restart_required();
    let config_path = mgr.config_path.clone().unwrap_or_else(|| "/etc/mdns-sieve.yaml".to_string());
    let bound_web_server = mgr.bound_web_server.clone();

    Json(json!({
        "status": "ok",
        "data": {
            "config": cfg_data,
            "yaml": yaml,
            "config_path": config_path,
            "restart_required": restart_required,
            "bound_web_server": bound_web_server,
        }
    }))
}

async fn api_save_config(
    State(manager): State<Arc<Mutex<CommandServerManager>>>,
    axum::extract::Json(payload): axum::extract::Json<Value>,
) -> Json<Value> {
    let parsed_config: Result<AppConfigData, String> = if let Some(yaml_str) = payload.get("yaml").and_then(|v| v.as_str()) {
        AppConfigData::from_yaml_str(yaml_str)
    } else if let Some(cfg_val) = payload.get("config") {
        serde_json::from_value::<AppConfigData>(cfg_val.clone())
            .map_err(|e| format!("Invalid configuration JSON: {}", e))
    } else {
        serde_json::from_value::<AppConfigData>(payload)
            .map_err(|e| format!("Invalid configuration payload: {}", e))
    };

    let new_data = match parsed_config {
        Ok(c) => c,
        Err(err) => {
            return Json(json!({
                "status": "error",
                "error": err,
            }));
        }
    };

    let mut mgr = manager.lock().await;
    match mgr.apply_updated_config(new_data) {
        Ok((updated_cfg, yaml, restart_required)) => {
            let config_path = mgr.config_path.clone().unwrap_or_else(|| "/etc/mdns-sieve.yaml".to_string());
            let bound_web_server = mgr.bound_web_server.clone();
            Json(json!({
                "status": "ok",
                "data": {
                    "config": updated_cfg,
                    "yaml": yaml,
                    "config_path": config_path,
                    "restart_required": restart_required,
                    "bound_web_server": bound_web_server,
                }
            }))
        }
        Err(err) => Json(json!({
            "status": "error",
            "error": err,
        })),
    }
}

async fn api_get_interfaces(State(manager): State<Arc<Mutex<CommandServerManager>>>) -> Json<Value> {
    let configured = {
        let mgr = manager.lock().await;
        mgr.configured_interfaces.clone()
    };

    let detected = tokio::task::spawn_blocking(discover_system_interfaces)
        .await
        .unwrap_or_default();

    Json(json!({
        "status": "ok",
        "data": {
            "detected": detected,
            "configured": configured,
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FilterRuleConfig, RuleSection, StringOrList};

    #[tokio::test]
    async fn test_apply_updated_config_hot_reload_and_persistence() {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let cfg_path = std::env::temp_dir().join(format!("mdns_srv_test_{}.yaml", nanos));
        let db_path = std::env::temp_dir().join(format!("mdns_srv_test_{}.db", nanos));

        let initial_data = AppConfigData {
            interfaces: vec!["eth0".to_string()],
            default_action: "forward".to_string(),
            rewrite_mixed_packets: false,
            forward_known_answers: false,
            web_server: Some(WebServerConfig {
                enabled: true,
                host: "0.0.0.0".to_string(),
                port: 8080,
            }),
            tracking: Some(TrackingConfig {
                enabled: true,
                max_records: 1000,
                db_path: db_path.to_string_lossy().to_string(),
                flush_interval_seconds: 60,
                retention_days: 7,
                history_retention_days: None,
                max_history_records: None,
            }),
            rules: vec![],
            ssdp: None,
        };

        initial_data.save_to_file(&cfg_path).unwrap();
        let initial_app_cfg = Arc::new(AppConfig::from_data(&initial_data));
        let (tx, mut rx) = tokio::sync::watch::channel(initial_app_cfg);

        let mut mgr = CommandServerManager::new(
            initial_data.web_server.clone(),
            initial_data.tracking.clone(),
            initial_data.interfaces.clone(),
        );
        mgr.set_config_context(
            cfg_path.to_string_lossy().to_string(),
            initial_data.clone(),
            tx,
        );

        let mut updated_data = initial_data.clone();
        updated_data.interfaces = vec!["eth0".to_string(), "wlan0".to_string()];
        updated_data.default_action = "drop".to_string();
        updated_data.web_server = Some(WebServerConfig {
            enabled: false, // should be forced back to true
            host: "127.0.0.1".to_string(), // changed host -> restart_required = true
            port: 9090,
        });
        updated_data.rules.push(FilterRuleConfig {
            action: "forward".to_string(),
            services: vec!["_airplay._tcp.local".to_string()],
            hosts: vec![],
            src: StringOrList::String("eth0".to_string()),
            dst: StringOrList::String("wlan0".to_string()),
            section: RuleSection::Any,
        });

        let (saved_cfg, _yaml, restart_required) = mgr.apply_updated_config(updated_data).unwrap();
        assert!(restart_required);
        assert!(saved_cfg.web_server.as_ref().unwrap().enabled);
        assert_eq!(mgr.configured_interfaces, vec!["eth0".to_string(), "wlan0".to_string()]);

        // Verify watch channel received the hot-reloaded AppConfig
        assert!(rx.has_changed().unwrap());
        let hot_cfg = rx.borrow_and_update().clone();
        assert!(!hot_cfg.default_action_is_forward);
        assert_eq!(hot_cfg.interfaces, vec!["eth0".to_string(), "wlan0".to_string()]);
        assert_eq!(hot_cfg.rules.len(), 1);

        // Verify .bak file was created on disk
        let bak_path = cfg_path.with_extension("yaml.bak");
        assert!(bak_path.exists());

        let _ = std::fs::remove_file(&cfg_path);
        let _ = std::fs::remove_file(&bak_path);
        let _ = std::fs::remove_file(&db_path);
    }
}
