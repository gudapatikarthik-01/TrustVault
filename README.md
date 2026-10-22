TrustVault — Secure Document Sharing System

1. Project Overview

TrustVault is a secure document-sharing application built with FastAPI and SQLite. It provides role-based access control, document permissions, and audit logging to help protect confidential files.

2. Problem Statement

Sharing documents without proper access controls can expose confidential information to unauthorized users. TrustVault addresses this problem by controlling who can access documents and recording important security-related actions.

3. Key Features

- User authentication with password hashing.
- Role-based access control for administrators, owners, and viewers.
- Secure document uploads with a 5 MB file-size limit.
- Document listing and search.
- Read and edit permission assignment.
- Permission revocation.
- Document reading and downloading.
- Access restrictions for unauthorized users.
- Audit logs with a SHA-256 hash chain for integrity verification.
- Automated tests for authentication and document security.

4. Technology Stack

- Python
- FastAPI
- SQLite
- PyJWT
- pwdlib with Argon2
- pytest
- httpx

5. Project Structure

Trust Vault/
├── app/
│   ├── main.py
│   ├── database.py
│   ├── auth.py
│   ├── test_auth.py
│   ├── test_login.py
│   └── test_document_security.py
├── uploads/
├── check_db.py
├── requirements.txt
├── .env
├── .gitignore
└── trustvault.db

6. Installation and Setup

1. Install Python 3.13 or another compatible Python version.

2. Open a terminal in the project folder.

3. Install dependencies:
   
   python -m pip install -r requirements.txt

4. Configure the required environment variables in ".env".

5. Start the application:
   
   python -m uvicorn app.main:app --reload

6. Open "http://127.0.0.1:8000/docs" in your browser to explore the API.

7. Testing

Run the automated tests:

python -m pytest -v

The current test result is 8 passed.

Verify audit-log integrity:

python check_db.py

8. Security Considerations

- Passwords are hashed rather than stored as plaintext.
- Access to documents is restricted using roles and permissions.
- Unauthorized access attempts should be recorded in audit logs.
- The audit hash chain can help detect changes to logged records.
- Environment secrets, the database, and uploaded files should not be committed to public repositories.

9. Future Improvements

- Add a document-content editing endpoint.
- Add stronger audit-log verification and tamper alerts.
- Add rate limiting and improved session/token management.
- Deploy the application using a production-ready configuration.
- Improve the user interface and monitoring.

10. Conclusion

TrustVault demonstrates secure document sharing through authentication, role-based authorization, permission management, and audit logging. It is designed to provide a foundation for protecting sensitive documents in a multi-user environment.