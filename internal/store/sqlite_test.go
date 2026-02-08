package store

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, err := NewSQLiteStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { st.Close() })
	return st
}

func TestNewSQLiteStore(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	st, err := NewSQLiteStore(dbPath)
	require.NoError(t, err)
	defer st.Close()

	assert.NotNil(t, st.readDB)
	assert.NotNil(t, st.writeDB)
}

func TestFilePermissions(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	st, err := NewSQLiteStore(dbPath)
	require.NoError(t, err)
	defer st.Close()

	info, err := os.Stat(dbPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestWALMode(t *testing.T) {
	st := newTestStore(t)

	var mode string
	err := st.readDB.QueryRow("PRAGMA journal_mode").Scan(&mode)
	require.NoError(t, err)
	assert.Equal(t, "wal", mode)
}

func TestMigrations(t *testing.T) {
	st := newTestStore(t)

	var version string
	err := st.readDB.QueryRow("SELECT value FROM _meta WHERE key = 'schema_version'").Scan(&version)
	require.NoError(t, err)
	assert.Equal(t, "1", version)
}

func TestPing(t *testing.T) {
	st := newTestStore(t)

	err := st.Ping(context.Background())
	assert.NoError(t, err)
}

func TestClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	st, err := NewSQLiteStore(dbPath)
	require.NoError(t, err)

	err = st.Close()
	require.NoError(t, err)

	// After close, Ping should fail.
	err = st.Ping(context.Background())
	assert.Error(t, err)
}

func TestConcurrentReads(t *testing.T) {
	st := newTestStore(t)

	const goroutines = 10
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			var version string
			errs[idx] = st.readDB.QueryRow("SELECT value FROM _meta WHERE key = 'schema_version'").Scan(&version)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d failed", i)
	}
}

func TestReadDBAndWriteDB(t *testing.T) {
	st := newTestStore(t)

	assert.NotNil(t, st.ReadDB())
	assert.NotNil(t, st.WriteDB())
	assert.Same(t, st.readDB, st.ReadDB())
	assert.Same(t, st.writeDB, st.WriteDB())
}
