from app.database import DATABASE_PATH, get_connection

print("Database path:", DATABASE_PATH.resolve())

connection = get_connection()

try:
    users = connection.execute(
        "SELECT id, username, role FROM users"
    ).fetchall()

    print("Users in this database:")
    for user in users:
        print(dict(user) if hasattr(user, "keys") else user)

finally:
    connection.close()