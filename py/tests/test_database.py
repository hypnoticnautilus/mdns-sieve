"""Tests for the database tracking functionality."""

# pylint: disable=protected-access
import tempfile
import time
from mdns_sieve.database import DatabaseManager


def test_database_initialization():
    """Test that the database and tables are created successfully."""
    with tempfile.NamedTemporaryFile() as tmp:
        db = DatabaseManager(tmp.name)

        with db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='responses';"
            )
            assert cursor.fetchone() is not None
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='queries';")
            assert cursor.fetchone() is not None


def test_batch_upsert_and_prune():
    """Test batch upsert logic and pruning."""
    with tempfile.NamedTemporaryFile() as tmp:
        db = DatabaseManager(tmp.name)
        now = time.time()

        # Insert a record
        records = [("192.168.1.10", "_http._tcp.local", "eth0", now, now, 1, "eth1", "eth2")]
        db.batch_upsert("responses", records)

        with db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT packet_count, last_forwarded_interfaces FROM responses")
            row = cursor.fetchone()
            assert row[0] == 1
            assert row[1] == "eth1"

        # Update the same record
        records_update = [
            ("192.168.1.10", "_http._tcp.local", "eth0", now, now + 10, 2, "eth1,eth3", "")
        ]
        db.batch_upsert("responses", records_update)

        with db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT packet_count, last_forwarded_interfaces FROM responses")
            row = cursor.fetchone()
            assert row[0] == 3  # 1 + 2
            assert row[1] == "eth1,eth3"

        # Prune old records (retention 1 day)
        db.prune_old_records(1)
        with db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM responses")
            assert cursor.fetchone()[0] == 1

        # If we set retention to -1 day, it should prune everything
        db.prune_old_records(-1)
        with db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM responses")
            assert cursor.fetchone()[0] == 0


def test_invalid_table_upsert():
    """Test that upserting into an invalid table is handled gracefully."""
    with tempfile.NamedTemporaryFile() as tmp:
        db = DatabaseManager(tmp.name)
        now = time.time()
        records = [("192.168.1.10", "_http._tcp.local", "eth0", now, now, 1, "eth1", "eth2")]
        # Should log an error but not crash
        db.batch_upsert("invalid_table", records)
