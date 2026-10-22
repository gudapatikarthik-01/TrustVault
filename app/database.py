import sqlite3
import hashlib
import json
from datetime import date, datetime
from pathlib import Path

# Database file location
DATABASE_PATH = Path(__file__).resolve().parent.parent / "trustvault.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def create_tables():
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'owner', 'viewer'))
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                owner_id INTEGER NOT NULL,
                category TEXT DEFAULT 'General',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                permission TEXT NOT NULL CHECK (permission IN ('read', 'edit')),
                UNIQUE (document_id, user_id),
                FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        document_id INTEGER,
        details TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        previous_hash TEXT,
        entry_hash TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE SET NULL
            )
            """
        )
        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(audit_logs)"
            ).fetchall()
        }

        if "previous_hash" not in columns:
            connection.execute(
                "ALTER TABLE audit_logs ADD COLUMN previous_hash TEXT"
            )

        if "entry_hash" not in columns:
            connection.execute(
                "ALTER TABLE audit_logs ADD COLUMN entry_hash TEXT"
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def log_action(user_id, action, document_id=None, details=None):
    connection = get_connection()

    try:
        previous = connection.execute(
            """
            SELECT entry_hash
            FROM audit_logs
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()

        previous_hash = previous["entry_hash"] if previous else "GENESIS"

        created_at = __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat()

        entry_data = {
            "user_id": user_id,
            "action": action,
            "document_id": document_id,
            "details": details,
            "created_at": created_at,
            "previous_hash": previous_hash,
        }

        entry_hash = hashlib.sha256(
            json.dumps(
                entry_data,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

        connection.execute(
            """
            INSERT INTO audit_logs (
                user_id, action, document_id, details,
                created_at, previous_hash, entry_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                action,
                document_id,
                details,
                created_at,
                previous_hash,
                entry_hash,
            ),
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()
    
def initialize_audit_hashes():
    """Rebuild hashes only when explicitly called."""
connection = get_connection()

try:
    rows = connection.execute(
        """
        SELECT id, user_id, action, document_id, details, created_at
        FROM audit_logs
        ORDER BY id ASC
        """
    ).fetchall()

    previous_hash = "GENESIS"

    for row in rows:
        entry_data = {
            "user_id": row["user_id"],
            "action": row["action"],
            "document_id": row["document_id"],
            "details": row["details"],
            "created_at": row["created_at"],
            "previous_hash": previous_hash,
        }

        entry_hash = hashlib.sha256(
            json.dumps(
                entry_data,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

        connection.execute(
            """
            UPDATE audit_logs
            SET previous_hash = ?, entry_hash = ?
            WHERE id = ?
            """,
            (previous_hash, entry_hash, row["id"]),
        )

        previous_hash = entry_hash

    connection.commit()

except Exception:
    connection.rollback()
    raise

finally:
    connection.close()
def verify_audit_logs():
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT id, user_id, action, document_id, details,
                   created_at, previous_hash, entry_hash
            FROM audit_logs
            ORDER BY id ASC
            """
        ).fetchall()

        previous_hash = "GENESIS"

        for row in rows:
            if not row["entry_hash"]:
                print(f"FAILED: Missing hash at audit log ID {row['id']}")
                return False

            if row["previous_hash"] != previous_hash:
                print(f"FAILED: Previous hash mismatch at audit log ID {row['id']}")
                return False

            entry_data = {
                "user_id": row["user_id"],
                "action": row["action"],
                "document_id": row["document_id"],
                "details": row["details"],
                "created_at": row["created_at"],
                "previous_hash": row["previous_hash"],
            }

            expected_hash = hashlib.sha256(
                json.dumps(
                    entry_data,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()

            if row["entry_hash"] != expected_hash:
                print(f"FAILED: Entry hash mismatch at audit log ID {row['id']}")
                return False

            previous_hash = row["entry_hash"]

        print("SUCCESS: All audit logs passed verification.")
        return True

    finally:
        connection.close()