-- +goose Up

-- SQLite cannot ALTER COLUMN to remove NOT NULL, so we rebuild the table.
-- ciphertext changes from NOT NULL to nullable (NULLed on soft-delete).
CREATE TABLE secrets_new (
    id                    TEXT    PRIMARY KEY,
    ciphertext            BLOB,
    mode                  TEXT    NOT NULL DEFAULT 'link',
    sender_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id          INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_at            TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at            TEXT    NOT NULL,
    retrieved_at          TEXT,
    passphrase_protected  INTEGER NOT NULL DEFAULT 0
);

INSERT INTO secrets_new (id, ciphertext, mode, sender_id, recipient_id, created_at, expires_at)
    SELECT id, ciphertext, mode, sender_id, recipient_id, created_at, expires_at FROM secrets;

DROP TABLE secrets;
ALTER TABLE secrets_new RENAME TO secrets;

CREATE INDEX idx_secrets_expires_at ON secrets(expires_at);
CREATE INDEX idx_secrets_recipient_id ON secrets(recipient_id);

-- +goose Down
-- Rebuild without the new columns; restore ciphertext NOT NULL.
CREATE TABLE secrets_old (
    id          TEXT    PRIMARY KEY,
    ciphertext  BLOB    NOT NULL,
    mode        TEXT    NOT NULL DEFAULT 'link',
    sender_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT    NOT NULL
);

INSERT INTO secrets_old (id, ciphertext, mode, sender_id, recipient_id, created_at, expires_at)
    SELECT id, ciphertext, mode, sender_id, recipient_id, created_at, expires_at
    FROM secrets WHERE ciphertext IS NOT NULL;

DROP TABLE secrets;
ALTER TABLE secrets_old RENAME TO secrets;

CREATE INDEX idx_secrets_expires_at ON secrets(expires_at);
CREATE INDEX idx_secrets_recipient_id ON secrets(recipient_id);
