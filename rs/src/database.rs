use rusqlite::{params, Connection, Result as RusqliteResult};
use std::path::Path;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct DatabaseManager {
    db_path: String,
}

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct TrackedRecord {
    pub src_ip: String,
    pub service_type: String,
    pub src_interface: String,
    pub first_seen: f64,
    pub last_seen: f64,
    pub packet_count: u64,
    pub last_forwarded_interfaces: String,
    pub last_dropped_interfaces: String,
}

impl DatabaseManager {
    pub fn new(db_path: &str) -> Self {
        let manager = Self {
            db_path: db_path.to_string(),
        };
        manager.initialize_db();
        manager
    }

    fn get_connection(&self) -> RusqliteResult<Connection> {
        let path = Path::new(&self.db_path);
        if let Some(dir) = path.parent() {
            if !dir.exists() {
                let _ = fs::create_dir_all(dir);
            }
        }
        let conn = Connection::open(&self.db_path)?;
        conn.execute("PRAGMA journal_mode = WAL;", [])?;
        conn.execute("PRAGMA synchronous = NORMAL;", [])?;
        Ok(conn)
    }

    fn initialize_db(&self) {
        if let Ok(conn) = self.get_connection() {
            let schema = "
                CREATE TABLE IF NOT EXISTS responses (
                    src_ip TEXT,
                    service_type TEXT,
                    src_interface TEXT,
                    first_seen REAL,
                    last_seen REAL,
                    packet_count INTEGER,
                    last_forwarded_interfaces TEXT,
                    last_dropped_interfaces TEXT,
                    PRIMARY KEY (src_ip, service_type, src_interface)
                );
                CREATE TABLE IF NOT EXISTS queries (
                    src_ip TEXT,
                    service_type TEXT,
                    src_interface TEXT,
                    first_seen REAL,
                    last_seen REAL,
                    packet_count INTEGER,
                    last_forwarded_interfaces TEXT,
                    last_dropped_interfaces TEXT,
                    PRIMARY KEY (src_ip, service_type, src_interface)
                );
                CREATE TABLE IF NOT EXISTS global_stats (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    total INTEGER,
                    forwarded INTEGER,
                    dropped INTEGER,
                    rewritten INTEGER
                );
            ";
            let _ = conn.execute_batch(schema);
        }
    }

    pub fn batch_upsert(&self, table_name: &str, records: &[TrackedRecord]) {
        if records.is_empty() {
            return;
        }
        if table_name != "responses" && table_name != "queries" {
            return;
        }

        if let Ok(mut conn) = self.get_connection() {
            let tx = match conn.transaction() {
                Ok(tx) => tx,
                Err(_) => return,
            };

            let query = format!("
                INSERT INTO {} (
                    src_ip, service_type, src_interface, first_seen, last_seen,
                    packet_count, last_forwarded_interfaces, last_dropped_interfaces
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ON CONFLICT(src_ip, service_type, src_interface) DO UPDATE SET
                    first_seen = MIN(first_seen, excluded.first_seen),
                    last_seen = MAX(last_seen, excluded.last_seen),
                    packet_count = packet_count + excluded.packet_count,
                    last_forwarded_interfaces = excluded.last_forwarded_interfaces,
                    last_dropped_interfaces = excluded.last_dropped_interfaces;
            ", table_name);

            {
                let mut stmt = match tx.prepare(&query) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                
                for r in records {
                    let _ = stmt.execute(params![
                        r.src_ip, r.service_type, r.src_interface,
                        r.first_seen, r.last_seen, r.packet_count,
                        r.last_forwarded_interfaces, r.last_dropped_interfaces
                    ]);
                }
            }
            let _ = tx.commit();
        }
    }

    pub fn prune_old_records(&self, retention_days: u32) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
        let threshold = now - (retention_days as f64 * 86400.0);
        
        if let Ok(conn) = self.get_connection() {
            let _ = conn.execute("DELETE FROM responses WHERE last_seen < ?1", params![threshold]);
            let _ = conn.execute("DELETE FROM queries WHERE last_seen < ?1", params![threshold]);
        }
    }

    pub fn save_global_stats(&self, total: u64, forwarded: u64, dropped: u64, rewritten: u64) {
        if let Ok(conn) = self.get_connection() {
            let _ = conn.execute(
                "INSERT INTO global_stats (id, total, forwarded, dropped, rewritten)
                 VALUES (1, ?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET
                     total = excluded.total,
                     forwarded = excluded.forwarded,
                     dropped = excluded.dropped,
                     rewritten = excluded.rewritten;",
                params![total, forwarded, dropped, rewritten],
            );
        }
    }

    pub fn load_global_stats(&self) -> (u64, u64, u64, u64) {
        if let Ok(conn) = self.get_connection() {
            let mut stmt = match conn.prepare("SELECT total, forwarded, dropped, rewritten FROM global_stats WHERE id = 1") {
                Ok(s) => s,
                Err(_) => return (0, 0, 0, 0),
            };
            
            let mut rows = match stmt.query([]) {
                Ok(r) => r,
                Err(_) => return (0, 0, 0, 0),
            };
            
            if let Ok(Some(row)) = rows.next() {
                let total: u64 = row.get(0).unwrap_or(0);
                let forwarded: u64 = row.get(1).unwrap_or(0);
                let dropped: u64 = row.get(2).unwrap_or(0);
                let rewritten: u64 = row.get(3).unwrap_or(0);
                return (total, forwarded, dropped, rewritten);
            }
        }
        (0, 0, 0, 0)
    }

    pub fn fetch_records(&self, table_name: &str) -> Vec<TrackedRecord> {
        let mut result = Vec::new();
        if table_name != "responses" && table_name != "queries" {
            return result;
        }

        if let Ok(conn) = self.get_connection() {
            let query = format!("SELECT * FROM {}", table_name);
            if let Ok(mut stmt) = conn.prepare(&query) {
                if let Ok(rows) = stmt.query_map([], |row| {
                    Ok(TrackedRecord {
                        src_ip: row.get(0)?,
                        service_type: row.get(1)?,
                        src_interface: row.get(2)?,
                        first_seen: row.get(3)?,
                        last_seen: row.get(4)?,
                        packet_count: row.get(5)?,
                        last_forwarded_interfaces: row.get(6)?,
                        last_dropped_interfaces: row.get(7)?,
                    })
                }) {
                    for record in rows {
                        if let Ok(r) = record {
                            result.push(r);
                        }
                    }
                }
            }
        }
        result
    }

    pub fn clear_tracking_data(&self) {
        if let Ok(conn) = self.get_connection() {
            let _ = conn.execute("DELETE FROM responses", []);
            let _ = conn.execute("DELETE FROM queries", []);
        }
    }
}
