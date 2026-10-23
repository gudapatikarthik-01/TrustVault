from app.database import create_tables, verify_audit_logs

if __name__ == "__main__":
    create_tables()
    result = verify_audit_logs()
print("Audit logs valid:", result)