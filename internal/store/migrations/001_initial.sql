-- +goose Up
CREATE TABLE _meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT INTO _meta (key, value) VALUES ('schema_version', '1');
INSERT INTO _meta (key, value) VALUES ('created_at', datetime('now'));

-- +goose Down
DROP TABLE _meta;
