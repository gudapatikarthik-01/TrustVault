import os
import hashlib
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    UploadFile,
    File,
    Query,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.database import create_tables, get_connection, log_action
from app.auth import (
    login_user,
    create_access_token,
    get_current_user,
    require_role,
)


# --------------------------------------------------
# APPLICATION SETUP
# --------------------------------------------------

app = FastAPI(
    title="TrustVault",
    description="Secure document sharing with access control and audit logs",
    version="1.0.0",
)

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

create_tables()


# --------------------------------------------------
# REQUEST MODELS
# --------------------------------------------------

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


class PermissionRequest(BaseModel):
    document_id: int = Field(gt=0)
    username: str = Field(min_length=1, max_length=100)
    permission: str


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def record_action(user_id, action, document_id=None, details=None):
    """Record activity without exposing internal database errors."""
    try:
        log_action(user_id, action, document_id, details)
    except Exception:
        # Fail closed for operations that require an audit record.
        raise HTTPException(
            status_code=500,
            detail="Unable to record audit activity",
        )


def get_document(document_id):
    connection = get_connection()
    try:
        return connection.execute(
            """
            SELECT id, filename, owner_id, category, created_at
            FROM documents
            WHERE id = ?
            """,
            (document_id,),
        ).fetchone()
    finally:
        connection.close()


def get_document_permission(document_id, user_id):
    connection = get_connection()
    try:
        return connection.execute(
            """
            SELECT permission
            FROM permissions
            WHERE document_id = ? AND user_id = ?
            """,
            (document_id, user_id),
        ).fetchone()
    finally:
        connection.close()


def check_document_access(document_id, current_user, required_permission="read"):
    """
    Check current database permissions on every request.
    Owners can read and edit their own documents.
    """
    document = get_document(document_id)

    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")

    if document["owner_id"] == current_user["id"]:
        return document

    permission = get_document_permission(
        document_id,
        current_user["id"],
    )

    allowed = False

    if permission:
        actual_permission = permission["permission"]

        if required_permission == "read":
            allowed = actual_permission in ("read", "edit")
        elif required_permission == "edit":
            allowed = actual_permission == "edit"

    if not allowed:
        try:
            log_action(
                current_user["id"],
                "ACCESS_DENIED",
                document_id,
                f"Required permission: {required_permission}",
            )
        except Exception:
            pass

        raise HTTPException(
            status_code=403,
            detail="You do not have permission to access this document",
        )

    return document


def safe_file_path(filename):
    """Ensure a document path stays inside the upload directory."""
    path = (UPLOAD_DIR / filename).resolve()

    if path.parent != UPLOAD_DIR.resolve():
        raise HTTPException(status_code=400, detail="Invalid file path")

    return path


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.get("/")
def home():
    return {
        "message": "Welcome to TrustVault",
        "status": "running",
        "documentation": "/docs",
    }


# --------------------------------------------------
# LOGIN AND USER DETAILS
# --------------------------------------------------

@app.post("/login")
def login(request: LoginRequest):
    user = login_user(request.username, request.password)

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    token = create_access_token(user)

    try:
        log_action(user["id"], "LOGIN", None, "Successful login")
    except Exception:
        pass

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user,
    }


@app.get("/me")
def get_me(current_user: dict = Depends(get_current_user)):
    return current_user


# --------------------------------------------------
# ADMIN
# --------------------------------------------------

@app.get("/admin")
def admin_dashboard(
    current_user: dict = Depends(require_role("admin")),
):
    connection = get_connection()

    try:
        user_count = connection.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]

        document_count = connection.execute(
            "SELECT COUNT(*) FROM documents"
        ).fetchone()[0]

        return {
            "message": "Admin dashboard",
            "users": user_count,
            "documents": document_count,
        }
    finally:
        connection.close()


@app.get("/admin/audit-logs")
def get_audit_logs(
    current_user: dict = Depends(require_role("admin")),
    limit: int = Query(default=100, ge=1, le=500),
):
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                id,
                user_id,
                action,
                document_id,
                details,
                created_at
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return {"audit_logs": [dict(row) for row in rows]}
    finally:
        connection.close()


# --------------------------------------------------
# UPLOAD DOCUMENT
# --------------------------------------------------

@app.post("/documents/upload")
async def upload_document(
    file: UploadFile = File(...),
    current_user: dict = Depends(require_role("owner")),
):
    original_filename = Path(file.filename or "").name

    if not original_filename:
        raise HTTPException(status_code=400, detail="Filename is required")

    if original_filename in (".", ".."):
        raise HTTPException(status_code=400, detail="Invalid filename")

    # Store files under generated names to prevent path and filename collisions.
    storage_name = hashlib.sha256(
        os.urandom(32)
    ).hexdigest() + ".bin"

    file_path = safe_file_path(storage_name)
    total_size = 0

    try:
        with file_path.open("xb") as output:
            while True:
                chunk = await file.read(1024 * 1024)

                if not chunk:
                    break

                total_size += len(chunk)

                if total_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="File exceeds the 5 MB limit",
                    )

                output.write(chunk)

        connection = get_connection()

        try:
            cursor = connection.execute(
                """
                INSERT INTO documents (filename, owner_id, category)
                VALUES (?, ?, ?)
                """,
                (
                    storage_name,
                    current_user["id"],
                    "General",
                ),
            )

            document_id = cursor.lastrowid

            connection.execute(
                """
                INSERT INTO audit_logs
                    (user_id, action, document_id, details)
                VALUES (?, ?, ?, ?)
                """,
                (
                    current_user["id"],
                    "UPLOAD",
                    document_id,
                    f"Original filename: {original_filename}; size: {total_size}",
                ),
            )

            connection.commit()

        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    except HTTPException:
        file_path.unlink(missing_ok=True)
        raise
    except Exception:
        file_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=500,
            detail="Unable to upload document",
        )
    finally:
        await file.close()

    return {
        "message": "Document uploaded successfully",
        "document_id": document_id,
        "filename": original_filename,
        "size_bytes": total_size,
    }


# --------------------------------------------------
# LIST MY DOCUMENTS
# --------------------------------------------------

@app.get("/documents")
def list_documents(
    current_user: dict = Depends(require_role("owner")),
):
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT id, filename, category, created_at
            FROM documents
            WHERE owner_id = ?
            ORDER BY id DESC
            """,
            (current_user["id"],),
        ).fetchall()

        return {"documents": [dict(row) for row in rows]}
    finally:
        connection.close()


# --------------------------------------------------
# SEARCH MY DOCUMENTS
# --------------------------------------------------

@app.get("/documents/search")
def search_documents(
    q: str = Query(min_length=1, max_length=100),
    current_user: dict = Depends(require_role("owner")),
):
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT id, filename, category, created_at
            FROM documents
            WHERE owner_id = ?
              AND filename LIKE ? ESCAPE '\\'
            ORDER BY id DESC
            """,
            (
                current_user["id"],
                "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%",
            ),
        ).fetchall()

        return {"documents": [dict(row) for row in rows]}
    finally:
        connection.close()


# --------------------------------------------------
# GRANT DOCUMENT PERMISSION
# --------------------------------------------------

@app.post("/documents/grant-permission")
def grant_permission(
    request: PermissionRequest,
    current_user: dict = Depends(require_role("owner")),
):
    if request.permission not in ("read", "edit"):
        raise HTTPException(
            status_code=400,
            detail="Permission must be read or edit",
        )

    connection = get_connection()

    try:
        document = connection.execute(
            """
            SELECT id, filename
            FROM documents
            WHERE id = ? AND owner_id = ?
            """,
            (request.document_id, current_user["id"]),
        ).fetchone()

        if document is None:
            raise HTTPException(
                status_code=404,
                detail="Document not found or not owned by you",
            )

        recipient = connection.execute(
            """
            SELECT id, username, role
            FROM users
            WHERE LOWER(TRIM(username)) = LOWER(TRIM(?))
            """,
            (request.username,),
        ).fetchone()

        if recipient is None:
            raise HTTPException(status_code=404, detail="Recipient not found")

        if recipient["id"] == current_user["id"]:
            raise HTTPException(
                status_code=400,
                detail="You cannot grant permission to yourself",
            )

        if recipient["role"] != "viewer":
            raise HTTPException(
                status_code=400,
                detail="Permissions can only be granted to viewer accounts",
            )

        connection.execute(
            """
            INSERT INTO permissions (document_id, user_id, permission)
            VALUES (?, ?, ?)
            ON CONFLICT(document_id, user_id)
            DO UPDATE SET permission = excluded.permission
            """,
            (
                request.document_id,
                recipient["id"],
                request.permission,
            ),
        )

        connection.execute(
            """
            INSERT INTO audit_logs
                (user_id, action, document_id, details)
            VALUES (?, ?, ?, ?)
            """,
            (
                current_user["id"],
                "GRANT_PERMISSION",
                request.document_id,
                f"Recipient: {recipient['username']}; permission: {request.permission}",
            ),
        )

        connection.commit()

        return {
            "message": "Permission granted successfully",
            "document_id": request.document_id,
            "username": recipient["username"],
            "permission": request.permission,
        }

    except HTTPException:
        connection.rollback()
        raise
    except Exception:
        connection.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to grant permission",
        )
    finally:
        connection.close()


# --------------------------------------------------
# REVOKE DOCUMENT PERMISSION
# --------------------------------------------------

@app.delete("/documents/{document_id}/permission")
def revoke_permission(
    document_id: int,
    username: str = Query(min_length=1, max_length=100),
    current_user: dict = Depends(require_role("owner")),
):
    connection = get_connection()

    try:
        document = connection.execute(
            """
            SELECT id
            FROM documents
            WHERE id = ? AND owner_id = ?
            """,
            (document_id, current_user["id"]),
        ).fetchone()

        if document is None:
            raise HTTPException(
                status_code=404,
                detail="Document not found or not owned by you",
            )

        recipient = connection.execute(
            """
            SELECT id, username
            FROM users
            WHERE LOWER(TRIM(username)) = LOWER(TRIM(?))
            """,
            (username,),
        ).fetchone()

        if recipient is None:
            raise HTTPException(status_code=404, detail="Recipient not found")

        cursor = connection.execute(
            """
            DELETE FROM permissions
            WHERE document_id = ? AND user_id = ?
            """,
            (document_id, recipient["id"]),
        )

        if cursor.rowcount == 0:
            connection.rollback()
            raise HTTPException(
                status_code=404,
                detail="No permission exists for this user",
            )

        connection.execute(
            """
            INSERT INTO audit_logs
                (user_id, action, document_id, details)
            VALUES (?, ?, ?, ?)
            """,
            (
                current_user["id"],
                "REVOKE_PERMISSION",
                document_id,
                f"Recipient: {recipient['username']}",
            ),
        )

        connection.commit()

        return {
            "message": "Permission revoked successfully",
            "document_id": document_id,
            "username": recipient["username"],
        }

    except HTTPException:
        raise
    except Exception:
        connection.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to revoke permission",
        )
    finally:
        connection.close()


# --------------------------------------------------
# READ DOCUMENT
# --------------------------------------------------

@app.get("/documents/{document_id}/read")
def read_document(
    document_id: int,
    current_user: dict = Depends(get_current_user),
):
    document = check_document_access(
        document_id,
        current_user,
        required_permission="read",
    )

    file_path = safe_file_path(document["filename"])

    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="Document file not found")

    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=415,
            detail="This endpoint currently supports text files only",
        )

    record_action(
        current_user["id"],
        "READ",
        document_id,
        "Document read successfully",
    )

    return {
        "document_id": document_id,
        "filename": document["filename"],
        "content": content,
    }


# --------------------------------------------------
# DOWNLOAD DOCUMENT
# --------------------------------------------------

@app.get("/documents/{document_id}/download")
def download_document(
    document_id: int,
    current_user: dict = Depends(get_current_user),
):
    document = check_document_access(
        document_id,
        current_user,
        required_permission="read",
    )

    file_path = safe_file_path(document["filename"])

    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="Document file not found")

    record_action(
        current_user["id"],
        "DOWNLOAD",
        document_id,
        "Document download requested",
    )

    return FileResponse(
        path=str(file_path),
        filename=f"document_{document_id}.bin",
        media_type="application/octet-stream",
    )


# --------------------------------------------------
# DELETE DOCUMENT
# --------------------------------------------------

@app.delete("/documents/{document_id}")
def delete_document(
    document_id: int,
    current_user: dict = Depends(require_role("owner")),
):
    connection = get_connection()

    try:
        document = connection.execute(
            """
            SELECT id, filename
            FROM documents
            WHERE id = ? AND owner_id = ?
            """,
            (document_id, current_user["id"]),
        ).fetchone()

        if document is None:
            raise HTTPException(
                status_code=404,
                detail="Document not found or not owned by you",
            )

        connection.execute(
            """
            INSERT INTO audit_logs
                (user_id, action, document_id, details)
            VALUES (?, ?, ?, ?)
            """,
            (
                current_user["id"],
                "DELETE_DOCUMENT",
                document_id,
                "Document deletion requested",
            ),
        )

        connection.execute(
            "DELETE FROM documents WHERE id = ?",
            (document_id,),
        )

        connection.commit()

        file_path = safe_file_path(document["filename"])
        file_path.unlink(missing_ok=True)

        return {
            "message": "Document deleted successfully",
            "document_id": document_id,
        }

    except HTTPException:
        connection.rollback()
        raise
    except Exception:
        connection.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to delete document",
        )
    finally:
        connection.close()