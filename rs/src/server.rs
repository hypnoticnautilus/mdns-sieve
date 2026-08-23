use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use axum::{
    extract::{State, Query},
    routing::{get, post},
    Router, Json, response::{Html, IntoResponse},
    http::{StatusCode, header},
};

use serde_json::{Value, json};
use crate::database::{DatabaseManager, TrackedRecord};
use crate::config::{WebServerConfig, TrackingConfig};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct BufferEntry {
    pub first_seen: f64,
    pub last_seen: f64,
    pub packet_count: u64,
    pub last_forwarded_interfaces: HashSet<String>,
    pub last_dropped_interfaces: HashSet<String>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct BufferKey {
    pub src_ip: String,
    pub service_type: String,
    pub src_interface: String,
}

pub struct CommandServerManager {
    config_server: Option<WebServerConfig>,
    tracking_config: Option<TrackingConfig>,
    
    pub stats_total: u64,
    pub stats_forwarded: u64,
    pub stats_dropped: u64,
    pub stats_rewritten: u64,

    db_manager: Option<DatabaseManager>,
    db_buffer_responses: HashMap<BufferKey, BufferEntry>,
    db_buffer_queries: HashMap<BufferKey, BufferEntry>,
    last_flush_time: f64,
}

impl CommandServerManager {
    pub fn new(config_server: Option<WebServerConfig>, tracking_config: Option<TrackingConfig>) -> Self {
        let mut db_manager = None;
        let mut stats_total = 0;
        let mut stats_forwarded = 0;
        let mut stats_dropped = 0;
        let mut stats_rewritten = 0;

        if let Some(ref tc) = tracking_config {
            if tc.enabled {
                let db = DatabaseManager::new(&tc.db_path);
                let (t, f, d, r) = db.load_global_stats();
                stats_total = t;
                stats_forwarded = f;
                stats_dropped = d;
                stats_rewritten = r;
                db_manager = Some(db);
            }
        }

        Self {
            config_server,
            tracking_config,
            stats_total,
            stats_forwarded,
            stats_dropped,
            stats_rewritten,
            db_manager,
            db_buffer_responses: HashMap::new(),
            db_buffer_queries: HashMap::new(),
            last_flush_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64(),
        }
    }

    pub fn collect_stats(
        &mut self,
        src_interface: &str,
        src_ip: &str,
        action: &str,
        allowed_names: &HashMap<String, Vec<String>>,
        disallowed_names: &HashMap<String, Vec<String>>,
        timestamp: f64,
        is_response: bool,
        kept_q: u64,
        kept_a: u64,
        stripped_q: u64,
        stripped_a: u64,
    ) {
        if let Some(ref cs) = self.config_server {
            if !cs.enabled {
                return;
            }
        } else {
            return;
        }

        self.stats_total += 1;
        match action {
            "forwarded" => self.stats_forwarded += 1,
            "dropped" => self.stats_dropped += 1,
            "rewritten" => {
                self.stats_rewritten += 1;
                if kept_q > 0 || kept_a > 0 {
                    self.stats_forwarded += kept_q + kept_a;
                }
                if stripped_q > 0 || stripped_a > 0 {
                    self.stats_dropped += stripped_q + stripped_a;
                }
            }
            _ => {}
        }

        if self.db_manager.is_some() {
            let buffer = if is_response {
                &mut self.db_buffer_responses
            } else {
                &mut self.db_buffer_queries
            };

            let mut service_type_stats: HashMap<String, (HashSet<String>, HashSet<String>)> = HashMap::new();
            let mut all_names = HashSet::new();
            for k in allowed_names.keys() { all_names.insert(k.clone()); }
            for k in disallowed_names.keys() { all_names.insert(k.clone()); }

            for name in all_names {
                let parts: Vec<&str> = name.split('.').collect();
                let mut service_type = name.clone();
                for (i, part) in parts.iter().enumerate() {
                    if part.starts_with('_') {
                        service_type = parts[i..].join(".");
                        break;
                    }
                }

                let entry = service_type_stats.entry(service_type.clone()).or_insert_with(|| (HashSet::new(), HashSet::new()));
                if let Some(a) = allowed_names.get(&name) {
                    for x in a { entry.0.insert(x.clone()); }
                }
                if let Some(d) = disallowed_names.get(&name) {
                    for x in d { entry.1.insert(x.clone()); }
                }
            }

            for (service_type, (allowed_set, mut disallowed_set)) in service_type_stats {
                for a in &allowed_set {
                    disallowed_set.remove(a);
                }

                let key = BufferKey {
                    src_ip: src_ip.to_string(),
                    service_type,
                    src_interface: src_interface.to_string(),
                };

                let entry = buffer.entry(key).or_insert_with(|| BufferEntry {
                    first_seen: timestamp,
                    last_seen: timestamp,
                    packet_count: 0,
                    last_forwarded_interfaces: HashSet::new(),
                    last_dropped_interfaces: HashSet::new(),
                });

                entry.last_seen = timestamp;
                entry.packet_count += 1;
                for fwd in allowed_set { entry.last_forwarded_interfaces.insert(fwd); }
                for drop in disallowed_set { entry.last_dropped_interfaces.insert(drop); }
            }
        }
    }

    pub fn flush_stats(&mut self, force: bool) {
        let tc = match &self.tracking_config {
            Some(c) if c.enabled => c,
            _ => return,
        };
        let db = match &self.db_manager {
            Some(db) => db,
            None => return,
        };

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
        if !force && (now - self.last_flush_time) < (tc.flush_interval_seconds as f64) {
            return;
        }
        self.last_flush_time = now;

        if !self.db_buffer_responses.is_empty() {
            let mut records = Vec::new();
            for (k, v) in &self.db_buffer_responses {
                let mut fwd_list: Vec<_> = v.last_forwarded_interfaces.iter().cloned().collect();
                fwd_list.sort();
                let mut drop_list: Vec<_> = v.last_dropped_interfaces.iter().cloned().collect();
                drop_list.sort();

                records.push(TrackedRecord {
                    src_ip: k.src_ip.clone(),
                    service_type: k.service_type.clone(),
                    src_interface: k.src_interface.clone(),
                    first_seen: v.first_seen,
                    last_seen: v.last_seen,
                    packet_count: v.packet_count,
                    last_forwarded_interfaces: fwd_list.join(","),
                    last_dropped_interfaces: drop_list.join(","),
                });
            }
            db.batch_upsert("responses", &records);
            self.db_buffer_responses.clear();
        }

        if !self.db_buffer_queries.is_empty() {
            let mut records = Vec::new();
            for (k, v) in &self.db_buffer_queries {
                let mut fwd_list: Vec<_> = v.last_forwarded_interfaces.iter().cloned().collect();
                fwd_list.sort();
                let mut drop_list: Vec<_> = v.last_dropped_interfaces.iter().cloned().collect();
                drop_list.sort();

                records.push(TrackedRecord {
                    src_ip: k.src_ip.clone(),
                    service_type: k.service_type.clone(),
                    src_interface: k.src_interface.clone(),
                    first_seen: v.first_seen,
                    last_seen: v.last_seen,
                    packet_count: v.packet_count,
                    last_forwarded_interfaces: fwd_list.join(","),
                    last_dropped_interfaces: drop_list.join(","),
                });
            }
            db.batch_upsert("queries", &records);
            self.db_buffer_queries.clear();
        }

        db.save_global_stats(self.stats_total, self.stats_forwarded, self.stats_dropped, self.stats_rewritten);
        db.prune_old_records(tc.retention_days);
    }


    fn merge_data(
        db_rows: &Vec<TrackedRecord>,
        buffer: &HashMap<BufferKey, BufferEntry>,
    ) -> Vec<TrackedRecord> {
        let mut merged = HashMap::new();
        for row in db_rows {
            let key = BufferKey {
                src_ip: row.src_ip.clone(),
                service_type: row.service_type.clone(),
                src_interface: row.src_interface.clone(),
            };
            merged.insert(key, TrackedRecord {
                src_ip: row.src_ip.clone(),
                service_type: row.service_type.clone(),
                src_interface: row.src_interface.clone(),
                first_seen: row.first_seen,
                last_seen: row.last_seen,
                packet_count: row.packet_count,
                last_forwarded_interfaces: row.last_forwarded_interfaces.clone(),
                last_dropped_interfaces: row.last_dropped_interfaces.clone(),
            });
        }
        for (bkey, bval) in buffer {
            if let Some(entry) = merged.get_mut(bkey) {
                if bval.first_seen < entry.first_seen {
                    entry.first_seen = bval.first_seen;
                }
                if bval.last_seen > entry.last_seen {
                    entry.last_seen = bval.last_seen;
                }
                entry.packet_count += bval.packet_count;
                
                let mut fwd: std::collections::HashSet<String> = entry.last_forwarded_interfaces.split(',').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
                fwd.extend(bval.last_forwarded_interfaces.clone());
                let mut fwd_vec: Vec<String> = fwd.into_iter().collect();
                fwd_vec.sort();
                entry.last_forwarded_interfaces = fwd_vec.join(",");

                let mut drop: std::collections::HashSet<String> = entry.last_dropped_interfaces.split(',').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
                drop.extend(bval.last_dropped_interfaces.clone());
                let mut drop_vec: Vec<String> = drop.into_iter().collect();
                drop_vec.sort();
                entry.last_dropped_interfaces = drop_vec.join(",");
            } else {
                let mut fwd_vec: Vec<String> = bval.last_forwarded_interfaces.clone().into_iter().collect();
                fwd_vec.sort();
                let mut drop_vec: Vec<String> = bval.last_dropped_interfaces.clone().into_iter().collect();
                drop_vec.sort();
                merged.insert(bkey.clone(), TrackedRecord {
                    src_ip: bkey.src_ip.clone(),
                    service_type: bkey.service_type.clone(),
                    src_interface: bkey.src_interface.clone(),
                    first_seen: bval.first_seen,
                    last_seen: bval.last_seen,
                    packet_count: bval.packet_count,
                    last_forwarded_interfaces: fwd_vec.join(","),
                    last_dropped_interfaces: drop_vec.join(","),
                });
            }
        }
        merged.into_values().collect()
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
                        "dropped": self.stats_dropped,
                        "rewritten": self.stats_rewritten,
                    },
                    "version": "0.1.0",
                    "commit": "rust-port"
                })
            }
            "clear" => {
                self.stats_total = 0;
                self.stats_forwarded = 0;
                self.stats_dropped = 0;
                self.stats_rewritten = 0;
                if let Some(db) = &self.db_manager {
                    db.save_global_stats(0, 0, 0, 0);
                    if payload.get("clear_tracking").and_then(|v| v.as_bool()).unwrap_or(false) {
                        self.db_buffer_responses.clear();
                        self.db_buffer_queries.clear();
                        db.clear_tracking_data();
                    }
                }
                json!({"status": "ok"})
            }
            "hosts" | "names" | "host_details" => {
                if let Some(db) = &self.db_manager {
                    let db_responses = db.fetch_records("responses");
                    let db_queries = db.fetch_records("queries");
                    
                    let merged_responses = Self::merge_data(&db_responses, &self.db_buffer_responses);
                    let merged_queries = Self::merge_data(&db_queries, &self.db_buffer_queries);
                    
                    if cmd == "hosts" {
                        let mut hosts_aggr: HashMap<String, Value> = HashMap::new();
                        for record in merged_responses.iter().chain(merged_queries.iter()) {
                            let entry = hosts_aggr.entry(record.src_ip.clone()).or_insert(json!({
                                "packets_sent": 0,
                                "last_interface": record.src_interface.clone(),
                                "last_seen_time": record.last_seen,
                            }));
                            let obj = entry.as_object_mut().unwrap();
                            let pkts = obj.get("packets_sent").unwrap().as_u64().unwrap();
                            obj.insert("packets_sent".to_string(), json!(pkts + record.packet_count));
                            let last = obj.get("last_seen_time").unwrap().as_f64().unwrap();
                            if record.last_seen > last {
                                obj.insert("last_seen_time".to_string(), json!(record.last_seen));
                                obj.insert("last_interface".to_string(), json!(record.src_interface.clone()));
                            }
                        }
                        return json!({"status": "ok", "data": hosts_aggr});
                    }
                    
                    if cmd == "names" {
                        let aggregate_names = |records: &Vec<TrackedRecord>| -> Value {
                            let mut names_aggr: HashMap<String, HashMap<String, Value>> = HashMap::new();
                            for r in records {
                                let stype = names_aggr.entry(r.service_type.clone()).or_insert_with(HashMap::new);
                                let entry = stype.entry(r.src_ip.clone()).or_insert(json!({
                                    "packets": 0,
                                    "fwd": Vec::<String>::new(),
                                    "drop": Vec::<String>::new(),
                                    "src": Vec::<String>::new(),
                                }));
                                
                                let obj = entry.as_object_mut().unwrap();
                                let pkts = obj.get("packets").unwrap().as_u64().unwrap();
                                obj.insert("packets".to_string(), json!(pkts + r.packet_count));
                                
                                let mut fwd: HashSet<String> = obj.get("fwd").unwrap().as_array().unwrap().iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
                                let mut drop: HashSet<String> = obj.get("drop").unwrap().as_array().unwrap().iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
                                let mut src: HashSet<String> = obj.get("src").unwrap().as_array().unwrap().iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
                                
                                fwd.extend(r.last_forwarded_interfaces.split(',').filter(|s| !s.is_empty()).map(|s| s.to_string()));
                                drop.extend(r.last_dropped_interfaces.split(',').filter(|s| !s.is_empty()).map(|s| s.to_string()));
                                if !r.src_interface.is_empty() {
                                    src.insert(r.src_interface.clone());
                                }
                                
                                let mut fwd_vec: Vec<String> = fwd.into_iter().collect();
                                fwd_vec.sort();
                                let mut drop_vec: Vec<String> = drop.into_iter().collect();
                                drop_vec.sort();
                                let mut src_vec: Vec<String> = src.into_iter().collect();
                                src_vec.sort();
                                
                                obj.insert("fwd".to_string(), json!(fwd_vec.join(",")));
                                obj.insert("drop".to_string(), json!(drop_vec.join(",")));
                                obj.insert("src".to_string(), json!(src_vec.join(",")));
                            }
                            json!(names_aggr)
                        };
                        
                        return json!({
                            "status": "ok",
                            "data": {
                                "responses": aggregate_names(&merged_responses),
                                "queries": aggregate_names(&merged_queries),
                            }
                        });
                    }
                    
                    if cmd == "host_details" {
                        if let Some(ip) = payload.get("ip").and_then(|v| v.as_str()) {
                            let r: Vec<_> = merged_responses.iter().filter(|x| x.src_ip == ip).collect();
                            let q: Vec<_> = merged_queries.iter().filter(|x| x.src_ip == ip).collect();
                            return json!({
                                "status": "ok",
                                "data": {
                                    "responses": r,
                                    "queries": q,
                                }
                            });
                        } else {
                            return json!({"status": "error", "error": "Missing 'ip' parameter"});
                        }
                    }
                }
                json!({"status": "error", "error": "Database tracking is disabled"})
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
        .route("/api/hosts", get(api_hosts))
        .route("/api/names", get(api_names))
        .route("/api/host_details", get(api_host_details))
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

async fn api_hosts(State(manager): State<Arc<Mutex<CommandServerManager>>>) -> Json<Value> {
    let mut mgr = manager.lock().await;
    Json(mgr.process_command(&json!({"command": "hosts"})))
}

async fn api_names(State(manager): State<Arc<Mutex<CommandServerManager>>>) -> Json<Value> {
    let mut mgr = manager.lock().await;
    Json(mgr.process_command(&json!({"command": "names"})))
}

#[derive(serde::Deserialize)]
pub struct HostDetailsQuery {
    ip: String,
}

async fn api_host_details(
    State(manager): State<Arc<Mutex<CommandServerManager>>>,
    Query(query): Query<HostDetailsQuery>,
) -> Json<Value> {
    let mut mgr = manager.lock().await;
    Json(mgr.process_command(&json!({"command": "host_details", "ip": query.ip})))
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

