package server_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"sneaker/internal/server"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testWebFS creates a minimal in-memory filesystem that mimics the web/ directory.
func testWebFS() fstest.MapFS {
	return fstest.MapFS{
		"web/index.html": &fstest.MapFile{
			Data: []byte(`<!DOCTYPE html><html><head><title>Sneaker</title></head><body><h1>Sneaker</h1></body></html>`),
		},
		"web/reveal.html": &fstest.MapFile{
			Data: []byte(`<!DOCTYPE html><html><head><title>Reveal Secret - Sneaker</title></head><body><h1>Sneaker</h1><div id="reveal-interstitial"></div></body></html>`),
		},
		"web/static/css/style.css": &fstest.MapFile{
			Data: []byte(`:root { --bg: #0d1117; }`),
		},
		"web/static/js/app.js": &fstest.MapFile{
			Data: []byte(`console.log("sneaker ready");`),
		},
	}
}

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	cfg := server.Config{
		Port:  0,
		Dev:   false,
		WebFS: testWebFS(),
	}
	srv := server.New(cfg, nil)
	return httptest.NewServer(srv.Handler())
}

func TestHealthEndpoint(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/health")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var result map[string]string
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)
	assert.Equal(t, "ok", result["status"])
}

func TestStaticFileServing(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "Sneaker")
}

func TestStaticCSS(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/static/css/style.css")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/css")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "0d1117")
}

func TestRevealPageRoute(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	// Any /s/{id} path should serve reveal.html
	resp, err := http.Get(ts.URL + "/s/abc123")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "Reveal Secret")
	assert.Contains(t, string(body), "reveal-interstitial")
}

func TestRevealPageDifferentIDs(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	// Different IDs should all serve the same reveal.html
	ids := []string{"deadbeef", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "test"}
	for _, id := range ids {
		resp, err := http.Get(ts.URL + "/s/" + id)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "id=%s", id)
		assert.Contains(t, string(body), "reveal-interstitial", "id=%s", id)
	}
}

func TestDevMode(t *testing.T) {
	// Dev mode serves from disk. In test environment, web/ dir may not exist
	// relative to test working directory. Just verify server creation doesn't panic.
	cfg := server.Config{
		Port:  0,
		Dev:   true,
		WebFS: testWebFS(),
	}
	assert.NotPanics(t, func() {
		_ = server.New(cfg, nil)
	})
}
