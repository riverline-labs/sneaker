package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// SQLiteStore implements Store using SQLite with WAL mode and dual
// connection pools (single writer, multiple readers).
type SQLiteStore struct {
	readDB  *sql.DB
	writeDB *sql.DB
}

// NewSQLiteStore opens (or creates) a SQLite database at dbPath with WAL mode,
// runs any pending migrations, and returns a ready-to-use store.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	// Ensure the database file exists with restrictive permissions.
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("creating database file: %w", err)
		}
		f.Close()
	}

	dsn := "file:" + dbPath + "?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)&_pragma=synchronous(normal)&_pragma=foreign_keys(on)"

	// Write connection: single writer for SQLite safety.
	writeDB, err := sql.Open("sqlite", dsn+"&_txlock=immediate")
	if err != nil {
		return nil, fmt.Errorf("opening write connection: %w", err)
	}
	writeDB.SetMaxOpenConns(1)

	// Read connections: multiple readers for concurrency under WAL.
	readDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		writeDB.Close()
		return nil, fmt.Errorf("opening read connection: %w", err)
	}
	readDB.SetMaxOpenConns(10)

	// Verify both connections work.
	if err := writeDB.Ping(); err != nil {
		readDB.Close()
		writeDB.Close()
		return nil, fmt.Errorf("pinging write connection: %w", err)
	}
	if err := readDB.Ping(); err != nil {
		readDB.Close()
		writeDB.Close()
		return nil, fmt.Errorf("pinging read connection: %w", err)
	}

	// Run migrations via goose Provider API.
	// fs.Sub strips the "migrations" prefix so goose sees *.sql at root level.
	migrations, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		readDB.Close()
		writeDB.Close()
		return nil, fmt.Errorf("accessing embedded migrations: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, writeDB, migrations)
	if err != nil {
		readDB.Close()
		writeDB.Close()
		return nil, fmt.Errorf("creating migration provider: %w", err)
	}

	results, err := provider.Up(context.Background())
	if err != nil {
		readDB.Close()
		writeDB.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	for _, r := range results {
		slog.Info("migration applied",
			"version", r.Source.Version,
			"path", r.Source.Path,
			"duration", r.Duration,
		)
	}

	slog.Info("database initialized", "path", dbPath)

	return &SQLiteStore{readDB: readDB, writeDB: writeDB}, nil
}

// Close shuts down both connection pools. The write pool is closed first.
func (s *SQLiteStore) Close() error {
	writeErr := s.writeDB.Close()
	readErr := s.readDB.Close()
	if writeErr != nil {
		return fmt.Errorf("closing write connection: %w", writeErr)
	}
	if readErr != nil {
		return fmt.Errorf("closing read connection: %w", readErr)
	}
	return nil
}

// Ping verifies database connectivity using the read pool.
func (s *SQLiteStore) Ping(ctx context.Context) error {
	return s.readDB.PingContext(ctx)
}

// ReadDB returns the read-only connection pool for use by domain queries.
func (s *SQLiteStore) ReadDB() *sql.DB {
	return s.readDB
}

// WriteDB returns the write connection pool for use by domain mutations.
func (s *SQLiteStore) WriteDB() *sql.DB {
	return s.writeDB
}
