from app.database import create_tables
from app.auth import register_user

create_tables()

test_users = [
    ("test_owner", "OwnerPass123!", "owner"),
    ("test_viewer", "ViewerPass123!", "viewer"),
    ("trust_admin", "0951", "admin"),
]

for username, password, role in test_users:
    try:
        register_user(username, password, role)
        print(f"Created user: {username}")
    except Exception as error:
        print(f"Could not create {username}: {error}")