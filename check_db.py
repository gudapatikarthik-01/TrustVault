from app.database import verify_audit_logs

if __name__ == "__main__":
    result = verify_audit_logs()
    print("Audit logs valid:", result)