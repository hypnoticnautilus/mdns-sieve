use rusqlite::{params, Connection, Result as RusqliteResult};
use rusqlite::types::Value as SqlValue;
use std::collections::HashMap;
use std::path::Path;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Query = 0,
    Response = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Dropped = 0,
    Forwarded = 1,
    PartiallyForwarded = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketSection {
    Question = 0,
    Answer = 1,
    Authority = 2,
    Additional = 3,
}

pub struct DatabaseManager {
    db_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MessageItemRecord {
    pub id: Option<i64>,
    pub message_id: Option<i64>,
    pub section: u8,
    pub name: String,
    pub rr_type: u16,
    pub rr_class: u16,
    pub ttl: Option<u32>,
    pub rdata_summary: Option<String>,
    pub disposition: u8,
    pub forwarded_interfaces: String,
    pub dropped_interfaces: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MessageRecord {
    pub id: Option<i64>,
    pub timestamp: f64,
    pub src_ip: String,
    pub src_interface: String,
    pub packet_type: u8,
    pub disposition: u8,
    pub forwarded_interfaces: String,
    pub dropped_interfaces: String,
    pub items: Vec<MessageItemRecord>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct HistoryFilterParams {
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
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;")?;
        Ok(conn)
    }

    fn initialize_db(&self) {
        if let Ok(conn) = self.get_connection() {
            // Migrate global_stats column if older schema had 'rewritten' instead of 'partially_forwarded'
            let _ = conn.execute("ALTER TABLE global_stats RENAME COLUMN rewritten TO partially_forwarded", []);

            let schema = "
                DROP TABLE IF EXISTS responses;
                DROP TABLE IF EXISTS queries;
                DROP TABLE IF EXISTS message_history;

                CREATE TABLE IF NOT EXISTS global_stats (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    total INTEGER NOT NULL,
                    forwarded INTEGER NOT NULL,
                    partially_forwarded INTEGER NOT NULL,
                    dropped INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    src_ip TEXT NOT NULL,
                    src_interface TEXT NOT NULL,
                    packet_type INTEGER NOT NULL,
                    disposition INTEGER NOT NULL,
                    forwarded_interfaces TEXT NOT NULL,
                    dropped_interfaces TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS message_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                    section INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    rr_type INTEGER NOT NULL,
                    rr_class INTEGER NOT NULL,
                    ttl INTEGER,
                    rdata_summary TEXT,
                    disposition INTEGER NOT NULL,
                    forwarded_interfaces TEXT NOT NULL,
                    dropped_interfaces TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages (timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_messages_src_ip ON messages (src_ip);
                CREATE INDEX IF NOT EXISTS idx_messages_src_interface ON messages (src_interface);
                CREATE INDEX IF NOT EXISTS idx_messages_disposition ON messages (disposition);
                CREATE INDEX IF NOT EXISTS idx_messages_packet_type ON messages (packet_type);
                CREATE INDEX IF NOT EXISTS idx_message_items_message_id ON message_items (message_id);
                CREATE INDEX IF NOT EXISTS idx_message_items_section_name ON message_items (section, name);
            ";
            let _ = conn.execute_batch(schema);
        }
    }

    pub fn batch_insert_messages(&self, messages: &[MessageRecord]) {
        if messages.is_empty() {
            return;
        }

        if let Ok(mut conn) = self.get_connection() {
            let tx = match conn.transaction() {
                Ok(tx) => tx,
                Err(_) => return,
            };

            {
                let mut msg_stmt = match tx.prepare(
                    "INSERT INTO messages (timestamp, src_ip, src_interface, packet_type, disposition, forwarded_interfaces, dropped_interfaces)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
                ) {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let mut item_stmt = match tx.prepare(
                    "INSERT INTO message_items (message_id, section, name, rr_type, rr_class, ttl, rdata_summary, disposition, forwarded_interfaces, dropped_interfaces)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
                ) {
                    Ok(s) => s,
                    Err(_) => return,
                };

                for m in messages {
                    if msg_stmt.execute(params![
                        m.timestamp,
                        m.src_ip,
                        m.src_interface,
                        m.packet_type,
                        m.disposition,
                        m.forwarded_interfaces,
                        m.dropped_interfaces,
                    ]).is_ok() {
                        let msg_id = tx.last_insert_rowid();
                        for item in &m.items {
                            let _ = item_stmt.execute(params![
                                msg_id,
                                item.section,
                                item.name,
                                item.rr_type,
                                item.rr_class,
                                item.ttl,
                                item.rdata_summary,
                                item.disposition,
                                item.forwarded_interfaces,
                                item.dropped_interfaces,
                            ]);
                        }
                    }
                }
            }
            let _ = tx.commit();
        }
    }

    pub fn prune_old_records(&self, retention_days: u32, max_records: usize) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
        let threshold = now - (retention_days as f64 * 86400.0);

        if let Ok(conn) = self.get_connection() {
            let _ = conn.execute("DELETE FROM messages WHERE timestamp < ?1", params![threshold]);

            if max_records > 0 {
                let count: usize = conn.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0)).unwrap_or(0);
                if count > max_records {
                    let excess = (count - max_records) as i64;
                    let _ = conn.execute(
                        "DELETE FROM messages WHERE id IN (SELECT id FROM messages ORDER BY timestamp ASC, id ASC LIMIT ?1)",
                        params![excess],
                    );
                }
            }
        }
    }

    pub fn query_messages(&self, filters: &HistoryFilterParams) -> (Vec<MessageRecord>, usize) {
        let mut records = Vec::new();
        let mut total = 0;

        let conn = match self.get_connection() {
            Ok(c) => c,
            Err(_) => return (records, 0),
        };

        let mut conditions = Vec::new();
        let mut sql_params: Vec<SqlValue> = Vec::new();

        if let Some(ref ip) = filters.src_ip {
            let ip_trimmed = ip.trim();
            if !ip_trimmed.is_empty() {
                conditions.push("m.src_ip LIKE ?".to_string());
                sql_params.push(SqlValue::Text(format!("%{}%", ip_trimmed)));
            }
        }
        if let Some(ref iface) = filters.src_interface {
            let iface_trimmed = iface.trim();
            if !iface_trimmed.is_empty() {
                conditions.push("m.src_interface = ?".to_string());
                sql_params.push(SqlValue::Text(iface_trimmed.to_string()));
            }
        }
        if let Some(ref dst) = filters.dst_interface {
            let dst_trimmed = dst.trim();
            if !dst_trimmed.is_empty() {
                conditions.push("(',' || m.forwarded_interfaces || ',') LIKE ?".to_string());
                sql_params.push(SqlValue::Text(format!("%,{},%", dst_trimmed)));
            }
        }
        if let Some(disp) = filters.disposition {
            conditions.push("m.disposition = ?".to_string());
            sql_params.push(SqlValue::Integer(disp as i64));
        }
        if let Some(ptype) = filters.packet_type {
            conditions.push("m.packet_type = ?".to_string());
            sql_params.push(SqlValue::Integer(ptype as i64));
        }
        if let Some(from) = filters.from_time {
            conditions.push("m.timestamp >= ?".to_string());
            sql_params.push(SqlValue::Real(from));
        }
        if let Some(to) = filters.to_time {
            conditions.push("m.timestamp <= ?".to_string());
            sql_params.push(SqlValue::Real(to));
        }
        if let Some(ref q_search) = filters.query_search {
            let s = q_search.trim();
            if !s.is_empty() {
                let pattern = format!("%{}%", s);
                conditions.push("EXISTS (SELECT 1 FROM message_items mi WHERE mi.message_id = m.id AND mi.section = 0 AND mi.name LIKE ?)".to_string());
                sql_params.push(SqlValue::Text(pattern));
            }
        }
        if let Some(ref r_search) = filters.response_search {
            let s = r_search.trim();
            if !s.is_empty() {
                let pattern = format!("%{}%", s);
                conditions.push("EXISTS (SELECT 1 FROM message_items mi WHERE mi.message_id = m.id AND mi.section IN (1, 2, 3) AND (mi.name LIKE ? OR mi.rdata_summary LIKE ?))".to_string());
                sql_params.push(SqlValue::Text(pattern.clone()));
                sql_params.push(SqlValue::Text(pattern));
            }
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let count_sql = format!("SELECT COUNT(*) FROM messages m {}", where_clause);
        if let Ok(mut count_stmt) = conn.prepare(&count_sql) {
            if let Ok(c) = count_stmt.query_row(rusqlite::params_from_iter(sql_params.iter()), |r| r.get(0)) {
                total = c;
            }
        }

        let limit = filters.limit.unwrap_or(50).clamp(1, 200);
        let page = filters.page.unwrap_or(1).max(1);
        let offset = (page - 1) * limit;

        let query_sql = format!(
            "SELECT m.id, m.timestamp, m.src_ip, m.src_interface, m.packet_type, m.disposition, m.forwarded_interfaces, m.dropped_interfaces
             FROM messages m {}
             ORDER BY m.timestamp DESC, m.id DESC
             LIMIT ? OFFSET ?",
            where_clause
        );

        let mut query_params = sql_params;
        query_params.push(SqlValue::Integer(limit as i64));
        query_params.push(SqlValue::Integer(offset as i64));

        let mut msg_ids = Vec::new();
        if let Ok(mut stmt) = conn.prepare(&query_sql) {
            if let Ok(rows) = stmt.query_map(rusqlite::params_from_iter(query_params.iter()), |row| {
                let id: i64 = row.get(0)?;
                Ok((id, MessageRecord {
                    id: Some(id),
                    timestamp: row.get(1)?,
                    src_ip: row.get(2)?,
                    src_interface: row.get(3)?,
                    packet_type: row.get(4)?,
                    disposition: row.get(5)?,
                    forwarded_interfaces: row.get(6)?,
                    dropped_interfaces: row.get(7)?,
                    items: Vec::new(),
                }))
            }) {
                for r in rows.flatten() {
                    msg_ids.push(r.0);
                    records.push(r.1);
                }
            }
        }

        if !msg_ids.is_empty() {
            let placeholders: Vec<String> = msg_ids.iter().map(|_| "?".to_string()).collect();
            let items_sql = format!(
                "SELECT id, message_id, section, name, rr_type, rr_class, ttl, rdata_summary, disposition, forwarded_interfaces, dropped_interfaces
                 FROM message_items
                 WHERE message_id IN ({})
                 ORDER BY id ASC",
                placeholders.join(", ")
            );
            let id_params: Vec<SqlValue> = msg_ids.iter().map(|&id| SqlValue::Integer(id)).collect();
            let mut items_by_msg: HashMap<i64, Vec<MessageItemRecord>> = HashMap::new();

            if let Ok(mut item_stmt) = conn.prepare(&items_sql) {
                if let Ok(item_rows) = item_stmt.query_map(rusqlite::params_from_iter(id_params.iter()), |row| {
                    let message_id: i64 = row.get(1)?;
                    Ok((message_id, MessageItemRecord {
                        id: Some(row.get(0)?),
                        message_id: Some(message_id),
                        section: row.get(2)?,
                        name: row.get(3)?,
                        rr_type: row.get(4)?,
                        rr_class: row.get(5)?,
                        ttl: row.get(6)?,
                        rdata_summary: row.get(7)?,
                        disposition: row.get(8)?,
                        forwarded_interfaces: row.get(9)?,
                        dropped_interfaces: row.get(10)?,
                    }))
                }) {
                    for (mid, item) in item_rows.flatten() {
                        items_by_msg.entry(mid).or_default().push(item);
                    }
                }
            }

            for msg in &mut records {
                if let Some(mid) = msg.id {
                    if let Some(items) = items_by_msg.remove(&mid) {
                        msg.items = items;
                    }
                }
            }
        }

        (records, total)
    }

    pub fn save_global_stats(&self, total: u64, forwarded: u64, partially_forwarded: u64, dropped: u64) {
        if let Ok(conn) = self.get_connection() {
            let _ = conn.execute(
                "INSERT INTO global_stats (id, total, forwarded, partially_forwarded, dropped)
                 VALUES (1, ?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET
                     total = excluded.total,
                     forwarded = excluded.forwarded,
                     partially_forwarded = excluded.partially_forwarded,
                     dropped = excluded.dropped;",
                params![total, forwarded, partially_forwarded, dropped],
            );
        }
    }

    pub fn load_global_stats(&self) -> (u64, u64, u64, u64) {
        if let Ok(conn) = self.get_connection() {
            let mut stmt = match conn.prepare("SELECT total, forwarded, partially_forwarded, dropped FROM global_stats WHERE id = 1") {
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
                let partially_forwarded: u64 = row.get(2).unwrap_or(0);
                let dropped: u64 = row.get(3).unwrap_or(0);
                return (total, forwarded, partially_forwarded, dropped);
            }
        }
        (0, 0, 0, 0)
    }

    pub fn clear_tracking_data(&self) {
        if let Ok(conn) = self.get_connection() {
            let _ = conn.execute("DELETE FROM messages", []);
            let _ = conn.execute("DELETE FROM message_items", []);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> (DatabaseManager, String) {
        let temp_dir = std::env::temp_dir();
        let file_name = format!("test_mdns_{}.db", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
        let path = temp_dir.join(file_name).to_string_lossy().to_string();
        let db = DatabaseManager::new(&path);
        (db, path)
    }

    #[test]
    fn test_messages_insert_and_query() {
        let (db, path) = temp_db();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();

        let records = vec![
            MessageRecord {
                id: None,
                timestamp: now - 10.0,
                src_ip: "192.168.1.100".to_string(),
                src_interface: "eth0".to_string(),
                packet_type: PacketType::Query as u8,
                disposition: Disposition::PartiallyForwarded as u8,
                forwarded_interfaces: "wlan0".to_string(),
                dropped_interfaces: "iot0,wlan0".to_string(),
                items: vec![
                    MessageItemRecord {
                        id: None,
                        message_id: None,
                        section: PacketSection::Question as u8,
                        name: "_printer._tcp.local".to_string(),
                        rr_type: 12,
                        rr_class: 1,
                        ttl: None,
                        rdata_summary: None,
                        disposition: Disposition::PartiallyForwarded as u8,
                        forwarded_interfaces: "wlan0".to_string(),
                        dropped_interfaces: "iot0".to_string(),
                    },
                    MessageItemRecord {
                        id: None,
                        message_id: None,
                        section: PacketSection::Question as u8,
                        name: "_ssh._tcp.local".to_string(),
                        rr_type: 12,
                        rr_class: 1,
                        ttl: None,
                        rdata_summary: None,
                        disposition: Disposition::Dropped as u8,
                        forwarded_interfaces: "".to_string(),
                        dropped_interfaces: "iot0,wlan0".to_string(),
                    },
                ],
            },
            MessageRecord {
                id: None,
                timestamp: now - 5.0,
                src_ip: "192.168.1.200".to_string(),
                src_interface: "wlan0".to_string(),
                packet_type: PacketType::Response as u8,
                disposition: Disposition::Forwarded as u8,
                forwarded_interfaces: "eth0,iot0".to_string(),
                dropped_interfaces: "".to_string(),
                items: vec![
                    MessageItemRecord {
                        id: None,
                        message_id: None,
                        section: PacketSection::Answer as u8,
                        name: "printer.local".to_string(),
                        rr_type: 1,
                        rr_class: 1,
                        ttl: Some(120),
                        rdata_summary: Some("192.168.1.200".to_string()),
                        disposition: Disposition::Forwarded as u8,
                        forwarded_interfaces: "eth0,iot0".to_string(),
                        dropped_interfaces: "".to_string(),
                    },
                ],
            },
        ];

        db.batch_insert_messages(&records);

        // Query all
        let (res, total) = db.query_messages(&HistoryFilterParams::default());
        assert_eq!(total, 2);
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].src_ip, "192.168.1.200");
        assert_eq!(res[0].items.len(), 1);
        assert_eq!(res[1].src_ip, "192.168.1.100");
        assert_eq!(res[1].items.len(), 2);

        // Filter by disposition
        let (res_part, total_part) = db.query_messages(&HistoryFilterParams {
            disposition: Some(Disposition::PartiallyForwarded as u8),
            ..Default::default()
        });
        assert_eq!(total_part, 1);
        assert_eq!(res_part[0].src_ip, "192.168.1.100");

        // Filter by query_search
        let (res_q, total_q) = db.query_messages(&HistoryFilterParams {
            query_search: Some("_ssh._tcp".to_string()),
            ..Default::default()
        });
        assert_eq!(total_q, 1);
        assert_eq!(res_q[0].src_ip, "192.168.1.100");

        // Filter by response_search (matching rdata_summary or name)
        let (res_r, total_r) = db.query_messages(&HistoryFilterParams {
            response_search: Some("192.168.1.200".to_string()),
            ..Default::default()
        });
        assert_eq!(total_r, 1);
        assert_eq!(res_r[0].src_ip, "192.168.1.200");

        // Filter by dst_interface
        let (res_dst, total_dst) = db.query_messages(&HistoryFilterParams {
            dst_interface: Some("iot0".to_string()),
            ..Default::default()
        });
        assert_eq!(total_dst, 1);
        assert_eq!(res_dst[0].src_ip, "192.168.1.200");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_retention_and_cascade_delete() {
        let (db, path) = temp_db();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();

        let make_msg = |ts: f64, ip: &str| MessageRecord {
            id: None,
            timestamp: ts,
            src_ip: ip.to_string(),
            src_interface: "eth0".to_string(),
            packet_type: PacketType::Query as u8,
            disposition: Disposition::Forwarded as u8,
            forwarded_interfaces: "wlan0".to_string(),
            dropped_interfaces: "".to_string(),
            items: vec![MessageItemRecord {
                id: None,
                message_id: None,
                section: PacketSection::Question as u8,
                name: "_http._tcp.local".to_string(),
                rr_type: 12,
                rr_class: 1,
                ttl: None,
                rdata_summary: None,
                disposition: Disposition::Forwarded as u8,
                forwarded_interfaces: "wlan0".to_string(),
                dropped_interfaces: "".to_string(),
            }],
        };

        let records = vec![
            make_msg(now - (8.0 * 86400.0), "10.0.0.1"),
            make_msg(now - 30.0, "10.0.0.2"),
            make_msg(now - 20.0, "10.0.0.3"),
            make_msg(now - 10.0, "10.0.0.4"),
        ];

        db.batch_insert_messages(&records);
        db.prune_old_records(7, 2);

        let (res, total) = db.query_messages(&HistoryFilterParams::default());
        assert_eq!(total, 2);
        assert_eq!(res[0].src_ip, "10.0.0.4");
        assert_eq!(res[1].src_ip, "10.0.0.3");

        // Ensure message_items were cascaded and only 2 remain
        let conn = db.get_connection().unwrap();
        let item_count: usize = conn.query_row("SELECT COUNT(*) FROM message_items", [], |r| r.get(0)).unwrap();
        assert_eq!(item_count, 2);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_clear_tracking_data() {
        let (db, path) = temp_db();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();

        db.batch_insert_messages(&[MessageRecord {
            id: None,
            timestamp: now,
            src_ip: "1.2.3.4".to_string(),
            src_interface: "eth0".to_string(),
            packet_type: PacketType::Query as u8,
            disposition: Disposition::Dropped as u8,
            forwarded_interfaces: "".to_string(),
            dropped_interfaces: "wlan0".to_string(),
            items: vec![MessageItemRecord {
                id: None,
                message_id: None,
                section: PacketSection::Question as u8,
                name: "_test._tcp.local".to_string(),
                rr_type: 12,
                rr_class: 1,
                ttl: None,
                rdata_summary: None,
                disposition: Disposition::Dropped as u8,
                forwarded_interfaces: "".to_string(),
                dropped_interfaces: "wlan0".to_string(),
            }],
        }]);

        let (_, total_before) = db.query_messages(&HistoryFilterParams::default());
        assert_eq!(total_before, 1);

        db.clear_tracking_data();

        let (_, total_after) = db.query_messages(&HistoryFilterParams::default());
        assert_eq!(total_after, 0);

        let _ = fs::remove_file(path);
    }
}
