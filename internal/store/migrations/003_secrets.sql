-- +goose Up
CREATE TABLE secrets (
    id          TEXT    PRIMARY KEY,
    ciphertext  BLOB    NOT NULL,
    mode        TEXT    NOT NULL DEFAULT 'link',
    sender_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT    NOT NULL
);

CREATE INDEX idx_secrets_expires_at ON secrets(expires_at);

-- +goose Down
DROP TABLE IF EXISTS secrets;
