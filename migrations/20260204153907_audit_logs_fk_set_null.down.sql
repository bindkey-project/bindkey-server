ALTER TABLE audit_logs
DROP CONSTRAINT audit_logs_bindkey_id_fkey;

ALTER TABLE audit_logs
ADD CONSTRAINT audit_logs_bindkey_id_fkey
FOREIGN KEY (bindkey_id)
REFERENCES bindkeys(id);

ALTER TABLE audit_logs
DROP CONSTRAINT audit_logs_user_id_fkey;

ALTER TABLE audit_logs
ADD CONSTRAINT audit_logs_user_id_fkey
FOREIGN KEY (user_id)
REFERENCES users(id);

