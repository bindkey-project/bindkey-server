CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id
    ON audit_logs(user_id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_action
    ON audit_logs(action);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at
    ON audit_logs(created_at DESC);
