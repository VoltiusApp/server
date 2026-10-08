-- Soft delete audits the user as target_id, so this FK made every soft-deleted
-- user impossible to hard-delete. The audit trail must outlive the user anyway.
ALTER TABLE admin_audit_log DROP CONSTRAINT admin_audit_log_target_id_fkey;
