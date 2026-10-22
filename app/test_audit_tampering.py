import hashlib
import json
import shutil
import sqlite3
import tempfile
from pathlib import Path

# Resolve the original database relative to this script
source_db = Path(__file__).resolve().parent.parent / "trustvault.db"

# Keep the entire tampering and verification process inside the TemporaryDirectory
with tempfile.TemporaryDirectory() as temp_dir:
    test_db = Path(temp_dir) / "test_trustvault.db"
    shutil.copy2(source_db, test_db)

    connection = sqlite3.connect(test_db)
    connection.row_factory = sqlite3.Row
    try:
        # Check for existing records to tamper with
        row = connection.execute(
            "SELECT id FROM audit_logs ORDER BY id ASC LIMIT 1"
        ).fetchone()

        if row is None:
            print("No audit records found. Run the application and generate logs first.")
        else:
            # Modify an existing audit record without updating its hash
            connection.execute(
                "UPDATE audit_logs SET details = ? WHERE id = ?",
                ("TAMPERED TEST DATA", row["id"]),
            )
            connection.commit()

            # Verify the temporary copy directly
            records = connection.execute(
                """
                SELECT id, user_id, action, document_id, details, created_at, previous_hash, entry_hash
                FROM audit_logs
                ORDER BY id ASC
                """
            ).fetchall()

            previous_hash = "GENESIS"
            tampering_detected = False

            for record in records:
                # 1. Verify chain continuity
                if record["previous_hash"] != previous_hash:
                    tampering_detected = True
                    break

                # 2. Verify payload hash integrity
                entry_data = {
                    "user_id": record["user_id"],
                    "action": record["action"],
                    "document_id": record["document_id"],
                    "details": record["details"],
                    "created_at": record["created_at"],
                    "previous_hash": record["previous_hash"],
                }
                expected_hash = hashlib.sha256(
                    json.dumps(
                        entry_data,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()

                if record["entry_hash"] != expected_hash:
                    tampering_detected = True
                    break

                previous_hash = record["entry_hash"]

            if tampering_detected:
                print("PASS: Audit tampering detected.")
            else:
                print("FAIL: Audit tampering was not detected.")

            print("The original database was not modified.")
    finally:
        connection.close()