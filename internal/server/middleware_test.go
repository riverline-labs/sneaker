package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecurityHeaders(t *testing.T) {
	// Create a dummy handler that returns 200 OK
	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := securityHeaders(dummy)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	assert.Equal(t, "strict-origin-when-cross-origin", resp.Header.Get("Referrer-Policy"))
	assert.Equal(t,
		"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'",
		resp.Header.Get("Content-Security-Policy"))
	assert.Equal(t, "camera=(), microphone=(), geolocation=()", resp.Header.Get("Permissions-Policy"))
}

func TestRequestLogger(t *testing.T) {
	// Verify the middleware passes requests through without panicking
	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	})

	handler := requestLogger(dummy)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	assert.NotPanics(t, func() {
		handler.ServeHTTP(rec, req)
	})

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "hello", rec.Body.String())
}

func TestStatusWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec, status: http.StatusOK}

	// Test that WriteHeader captures the status
	sw.WriteHeader(http.StatusNotFound)
	assert.Equal(t, http.StatusNotFound, sw.status)

	// Test that calling WriteHeader again doesn't change the captured status
	sw.WriteHeader(http.StatusInternalServerError)
	assert.Equal(t, http.StatusNotFound, sw.status)
}
