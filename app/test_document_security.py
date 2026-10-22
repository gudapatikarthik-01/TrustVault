import os
import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

# Admin credentials: set these environment variables locally.
ADMIN_USERNAME = os.getenv("TEST_ADMIN_USERNAME", "trust_admin")
ADMIN_PASSWORD = os.getenv("TEST_ADMIN_PASSWORD", "0951")


def get_token(username: str, password: str) -> str:
    response = client.post(
        "/login",
        json={
            "username": username,
            "password": password,
        },
    )
    assert response.status_code == 200, (
        f"Login failed for {username}: {response.status_code}"
    )
    return response.json()["access_token"]


def test_viewer_cannot_access_admin_dashboard():
    viewer_token = get_token("test_viewer", "ViewerPass123!")
    response = client.get(
        "/admin",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert response.status_code == 403


def test_owner_cannot_access_admin_dashboard():
    owner_token = get_token("test_owner", "OwnerPass123!")
    response = client.get(
        "/admin",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert response.status_code == 403


def test_unauthenticated_user_cannot_read_document():
    response = client.get("/documents/1/read")
    assert response.status_code == 401


def test_revoked_viewer_cannot_read_document():
    owner_token = get_token("test_owner", "OwnerPass123!")
    viewer_token = get_token("test_viewer", "ViewerPass123!")

    owner_headers = {"Authorization": f"Bearer {owner_token}"}
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

    grant_response = client.post(
        "/documents/grant-permission",
        headers=owner_headers,
        json={
            "document_id": 1,
            "username": "test_viewer",
            "permission": "read",
        },
    )
    assert grant_response.status_code == 200

    read_response = client.get(
        "/documents/1/read",
        headers=viewer_headers,
    )
    assert read_response.status_code == 200

    revoke_response = client.delete(
        "/documents/1/permission",
        headers=owner_headers,
        params={"username": "test_viewer"},
    )
    assert revoke_response.status_code == 200

    denied_response = client.get(
        "/documents/1/read",
        headers=viewer_headers,
    )
    assert denied_response.status_code == 403


def test_denied_access_is_recorded_in_audit_logs():
    viewer_token = get_token("test_viewer", "ViewerPass123!")

    denied_response = client.get(
        "/admin",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert denied_response.status_code == 403

    # Skip this test if admin credentials are not configured.
    if not ADMIN_PASSWORD:
        pytest.skip("Set TEST_ADMIN_PASSWORD to run this test")

    admin_token = get_token(ADMIN_USERNAME, ADMIN_PASSWORD)
    logs_response = client.get(
        "/admin/audit-logs",
        headers={"Authorization": f"Bearer {admin_token}"},
        params={"limit": 200},
    )
    assert logs_response.status_code == 200

    logs = logs_response.json().get("audit_logs", [])
    assert any(
        log.get("action") == "ACCESS_DENIED"
        and log.get("details")
        and "role" in log.get("details", "").lower()
        for log in logs
    ), "No ACCESS_DENIED role-denial event found in audit logs"