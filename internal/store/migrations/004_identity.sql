-- +goose Up
CREATE TABLE public_keys (
    user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    public_key TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

ALTER TABLE secrets ADD COLUMN recipient_id INTEGER REFERENCES users(id) ON DELETE CASCADE;

CREATE INDEX idx_secrets_recipient_id ON secrets(recipient_id);

-- +goose Down
DROP INDEX IF EXISTS idx_secrets_recipient_id;

-- SQLite does not support DROP COLUMN before 3.35.0; the column is nullable
-- so leaving it in place is safe for rollback. The index drop above suffices.

DROP TABLE IF EXISTS public_keys;
