CREATE TABLE audit_logs (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    bindkey_id UUID REFERENCES bindkeys(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    details TEXT,
    severity TEXT NOT NULL DEFAULT 'INFO',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

