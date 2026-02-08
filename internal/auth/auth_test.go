package auth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("test-password", DefaultParams)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(hash, "$argon2id$v=19$"), "hash should start with $argon2id$v=19$, got: %s", hash)
}

func TestVerifyPasswordCorrect(t *testing.T) {
	hash, err := HashPassword("test-password", DefaultParams)
	require.NoError(t, err)

	match, err := VerifyPassword("test-password", hash)
	require.NoError(t, err)
	assert.True(t, match, "correct password should verify")
}

func TestVerifyPasswordWrong(t *testing.T) {
	hash, err := HashPassword("test-password", DefaultParams)
	require.NoError(t, err)

	match, err := VerifyPassword("wrong-password", hash)
	require.NoError(t, err)
	assert.False(t, match, "wrong password should not verify")
}

func TestHashUniqueness(t *testing.T) {
	hash1, err := HashPassword("same-password", DefaultParams)
	require.NoError(t, err)

	hash2, err := HashPassword("same-password", DefaultParams)
	require.NoError(t, err)

	assert.NotEqual(t, hash1, hash2, "two hashes of the same password should differ (different salts)")
}

func TestDummyHashExists(t *testing.T) {
	assert.NotEmpty(t, DummyHash, "DummyHash should be initialized")
	assert.True(t, strings.HasPrefix(DummyHash, "$argon2id$"), "DummyHash should be an argon2id hash")
}

func TestVerifyDummyHash(t *testing.T) {
	match, err := VerifyPassword("random-input-not-the-dummy-password", DummyHash)
	require.NoError(t, err)
	assert.False(t, match, "DummyHash should not match random input")
}

func TestDecodeInvalidHash(t *testing.T) {
	tests := []struct {
		name string
		hash string
	}{
		{"empty string", ""},
		{"garbage", "not-a-hash"},
		{"too few parts", "$argon2id$v=19$m=65536"},
		{"bad version", "$argon2id$v=999$m=65536,t=3,p=2$c2FsdA$aGFzaA"},
		{"bad params", "$argon2id$v=19$garbage$c2FsdA$aGFzaA"},
		{"bad salt base64", "$argon2id$v=19$m=65536,t=3,p=2$!!!invalid!!!$aGFzaA"},
		{"bad hash base64", "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$!!!invalid!!!"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := VerifyPassword("anything", tt.hash)
			assert.Error(t, err, "should return error for invalid hash")
			assert.False(t, match, "should not match for invalid hash")
		})
	}
}

func TestDefaultParams(t *testing.T) {
	assert.Equal(t, uint32(64*1024), DefaultParams.Memory, "Memory should be 64 MB")
	assert.Equal(t, uint32(3), DefaultParams.Iterations, "Iterations should be 3")
	assert.Equal(t, uint8(2), DefaultParams.Parallelism, "Parallelism should be 2")
	assert.Equal(t, uint32(16), DefaultParams.SaltLength, "SaltLength should be 16")
	assert.Equal(t, uint32(32), DefaultParams.KeyLength, "KeyLength should be 32")
}
