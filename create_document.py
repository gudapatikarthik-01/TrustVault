from app.database import get_connection

connection = get_connection()

owner = connection.execute(
"SELECT id FROM users WHERE username = ?",
("test_owner",)
).fetchone()

if owner is None:
print("ERROR: test_owner was not found.")
else:
connection.execute(
"INSERT INTO documents (filename, owner_id, category) VALUES (?, ?, ?)",
("hello2.txt", owner["id"], "General")
)
connection.commit()
print("Test document created successfully!")

documents = connection.execute(
"SELECT * FROM documents"
).fetchall()

for document in documents:
print(dict(document))

connection.close()