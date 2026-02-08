-- +goose Up
CREATE TABLE teams (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    creator_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE team_members (
    team_id    INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       TEXT    NOT NULL DEFAULT 'member',
    joined_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (team_id, user_id)
);

CREATE INDEX idx_team_members_user_id ON team_members(user_id);

CREATE TABLE team_invites (
    token      TEXT    PRIMARY KEY,
    team_id    INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    created_by INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_team_invites_team_id ON team_invites(team_id);

-- +goose Down
DROP TABLE IF EXISTS team_invites;
DROP TABLE IF EXISTS team_members;
DROP TABLE IF EXISTS teams;
