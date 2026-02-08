package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	// ErrInvalidHash is returned when the encoded hash string cannot be parsed.
	ErrInvalidHash = errors.New("invalid hash format")
	// ErrIncompatibleVersion is returned when the hash was created with an
	// unsupported Argon2 version.
	ErrIncompatibleVersion = errors.New("incompatible argon2 version")
)

// Params configures the Argon2id hashing algorithm.
type Params struct {
	Memory      uint32 // KiB
	Iterations  uint32 // time passes
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultParams follows RFC 9106 recommendations for interactive login.
// Memory = 64 MB, Iterations = 3, Parallelism = 2.
var DefaultParams = &Params{
	Memory:      64 * 1024, // 64 MB
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

// DummyHash is a pre-computed Argon2id hash used when a user is not found
// during login. This ensures login attempts for nonexistent users take the
// same time as attempts for real users, preventing user enumeration via timing.
var DummyHash string

func init() {
	var err error
	DummyHash, err = HashPassword("dummy-password-for-timing-normalization", DefaultParams)
	if err != nil {
		panic("failed to generate dummy hash: " + err.Error())
	}
}

// HashPassword returns an encoded Argon2id hash string in PHC format:
// $argon2id$v=19$m=65536,t=3,p=2$<base64-salt>$<base64-hash>
func HashPassword(password string, p *Params) (string, error) {
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		b64Salt, b64Hash), nil
}

// VerifyPassword performs constant-time comparison of password against an
// encoded Argon2id hash. Returns (true, nil) on match, (false, nil) on
// mismatch, (false, err) on decode errors.
func VerifyPassword(password, encodedHash string) (bool, error) {
	p, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}

// decodeHash parses a PHC-format Argon2id hash string into its components.
func decodeHash(encodedHash string) (*Params, []byte, []byte, error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p := &Params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism)
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}
	p.SaltLength = uint32(len(salt))

	hash, err := base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}
	p.KeyLength = uint32(len(hash))

	return p, salt, hash, nil
}
