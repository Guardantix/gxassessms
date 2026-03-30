-- Add native_check_id to findings table.
-- Required for Finding domain model round-trip fidelity.
-- Existing rows default to empty string. Re-running normalization
-- on a previous engagement will populate the correct value.
ALTER TABLE findings ADD COLUMN native_check_id TEXT NOT NULL DEFAULT '';
