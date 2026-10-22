from app.auth import register_user, login_user

# Register a test owner
try:
    print(register_user("test_owner", "OwnerPass123!", "owner"))
except Exception as e:
    print("Registration:", e)

# Test correct password
user = login_user("test_owner", "OwnerPass123!")
print("Correct login:", user)

# Test wrong password
wrong_user = login_user("test_owner", "WrongPass123!")
print("Wrong login rejected:", wrong_user is None)