"""
Database Manager for mDNS Sieve Tracking

Handles SQLite connection, table creation, bulk updates, and pruning.
"""

import sqlite3
import logging
import os
import time
from typing import List, Tuple, Any

logger = logging.getLogger("mdns_sieve.database")


class DatabaseManager:
    """Manages the SQLite database for tracking mDNS responses and queries."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._initialize_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Returns a configured SQLite connection."""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, exist_ok=True)
            except OSError as e:
                logger.error("Failed to create database directory %s: %s", db_dir, e)

        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def _initialize_db(self) -> None:
        """Creates the necessary tables if they don't exist."""
        try:
            with self._get_connection() as conn:
                schema = """
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
                """
                conn.executescript(schema)
        except sqlite3.Error as e:
            logger.error("Database initialization failed: %s", e)

    def batch_upsert(self, table_name: str, records: List[Tuple[Any, ...]]) -> None:
        """
        Bulk upserts records into the specified table.
        records: List of tuples (src_ip, service_type, src_interface,
        first_seen, last_seen, packet_count, last_forwarded_interfaces,
        last_dropped_interfaces)
        """
        if not records:
            return
        if table_name not in ("responses", "queries"):
            logger.error("Invalid table name: %s", table_name)
            return

        query = f"""
            INSERT INTO {table_name} (
                src_ip, service_type, src_interface, first_seen, last_seen,
                packet_count, last_forwarded_interfaces, last_dropped_interfaces
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(src_ip, service_type, src_interface) DO UPDATE SET
                first_seen = MIN(first_seen, excluded.first_seen),
                last_seen = MAX(last_seen, excluded.last_seen),
                packet_count = packet_count + excluded.packet_count,
                last_forwarded_interfaces = excluded.last_forwarded_interfaces,
                last_dropped_interfaces = excluded.last_dropped_interfaces;
        """
        try:
            with self._get_connection() as conn:
                conn.executemany(query, records)
        except sqlite3.Error as e:
            logger.error("Failed to batch upsert into %s: %s", table_name, e)

    def prune_old_records(self, retention_days: int) -> None:
        """Deletes records older than retention_days."""
        threshold = time.time() - (retention_days * 86400)
        try:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM responses WHERE last_seen < ?", (threshold,))
                conn.execute("DELETE FROM queries WHERE last_seen < ?", (threshold,))
        except sqlite3.Error as e:
            logger.error("Failed to prune old records: %s", e)
