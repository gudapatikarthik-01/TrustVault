TrustVault — Threat Model

1. Project Overview

TrustVault is a secure document-sharing application built with FastAPI and SQLite. It uses authentication, role-based access control, document permissions, and audit logs to protect documents.

2. Assets to Protect

- User accounts and password hashes.
- Authentication tokens and secret keys.
- Uploaded documents and their contents.
- Document-sharing permissions.
- Audit logs and their integrity.

3. Potential Threats and Mitigations

Threat 1: Unauthorized Document Access

Risk: A Viewer may try to access a document that has not been shared with them.

Mitigation: Check document ownership and permissions before allowing document reading or downloading. Return "403 Forbidden" when an authenticated user lacks permission.

Threat 2: Weak or Stolen Credentials

Risk: An attacker may obtain a user's password or authentication token.

Mitigation: Hash passwords securely, verify credentials during login, protect secret keys, and avoid exposing tokens in logs or public repositories.

Threat 3: Privilege Escalation

Risk: A Viewer may try to perform Owner or Admin operations.

Mitigation: Enforce role-based authorization on protected endpoints and test that users cannot perform actions outside their roles.

Threat 4: Unauthorized Document Sharing

Risk: A user may attempt to grant access to a document they do not own.

Mitigation: Verify document ownership and validate the recipient and requested permission before changing sharing permissions.

Threat 5: Audit Log Tampering

Risk: Someone may attempt to alter or delete audit records to hide their actions.

Mitigation: Verify audit-log integrity and test detection of modified records. For production, store audit records in a separately protected system.

Threat 6: Malicious or Unsafe Uploads

Risk: An attacker may upload an unsafe or unexpectedly large file.

Mitigation: Validate uploads, restrict permitted file types and file sizes, generate safe server-side filenames, and avoid trusting user-supplied paths.

Threat 7: Exposure of Secrets

Risk: Database files, environment variables, or authentication secrets may be accidentally published.

Mitigation: Exclude ".env", local database files, and uploaded private documents from Git. Use protected environment variables for secrets.

4. Security Limitations

- This project is a prototype and has not been independently security-audited.
- Audit-log verification does not guarantee complete protection against an attacker who can modify both the records and the verification mechanism.
- Production use would require additional controls, including HTTPS, secure token handling, rate limiting, upload limits, backups, and protected audit-log storage.

5. Security Testing

The project has been tested for authentication, document permissions, unauthorized access, and audit-log integrity. Automated tests should be rerun after security-related code changes.