from app.database import get_connection

# Standard try/finally with fixed indentation
connection = get_connection()
try:
    cursor = connection.cursor()
    cursor.execute("SELECT id, username, role FROM users")
    users = cursor.fetchall()

    print("Users found:", len(users))

    # If row_factory is sqlite3.Row, dict(user) works directly.
    # Otherwise, map column names manually:
    columns = [col[0] for col in cursor.description]
    for user in users:
        print(dict(zip(columns, user)))
finally:
    connection.close()