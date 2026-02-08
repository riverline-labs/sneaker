# Sneaker

One-time secret exchange. Send secrets that self-destruct after reading.

Sneaker is a self-hosted tool for sharing sensitive information securely. Secrets are end-to-end encrypted using [AGE](https://age-encryption.org/) (X25519) -- the server never sees plaintext. Each secret can only be retrieved once, then it's gone.

## Features

- **End-to-end encryption** -- secrets encrypted client-side before upload
- **One-time retrieval** -- secrets self-destruct after reading
- **Link mode** -- share via URL, no account needed to receive
- **Identity mode** -- send directly to a registered user's public key
- **Passphrase protection** -- optional additional encryption layer
- **TTL support** -- secrets auto-expire (5 min to 30 days)
- **Teams** -- send secrets to all members of a team at once
- **Web UI** -- browser-based sending and receiving
- **CLI** -- full-featured command-line interface
- **Single binary** -- web assets and migrations embedded, just run it
- **No external dependencies** -- SQLite database, no Redis/Postgres/cloud services

## Quick Start

### Build

```bash
go build -o sneaker .
```

### Provision (recommended for new instances)

Bootstrap a fresh Sneaker instance in one step -- starts the server, creates an admin account, and sets up a team:

```bash
./sneaker provision --email admin@example.com --password secret --team myteam
# Starts server, creates account, creates team, keeps running
```

All flags are optional; omit any to be prompted interactively. Accepts the same server flags as `serve`:

```
--port 3000     Custom port (default: 7657)
--db path.db    Custom database path (default: sneaker.db)
--dev           Serve frontend from disk for live reload
```

### Start the server (standalone)

```bash
./sneaker serve
# Listening on :7657
```

Options:
```
--port 3000     Custom port (default: 7657)
--db path.db    Custom database path (default: sneaker.db)
--dev           Serve frontend from disk for live reload
```

### Create an account

```bash
./sneaker signup --server http://localhost:7657
# Prompts for email and password, creates account and logs in
```

### Log in (existing account)

```bash
./sneaker login --server http://localhost:7657
```

### Send a secret (link mode)

```bash
# From argument
./sneaker send "my secret message"

# From stdin
echo "my secret" | ./sneaker send

# With options
./sneaker send --ttl 1h --passphrase "my secret message"
```

This prints a URL like `http://localhost:7657/s/abc123#key`. The decryption key is in the URL fragment and never sent to the server.

### Receive a secret (link mode)

Open the URL in a browser, or:

```bash
./sneaker recv http://localhost:7657/s/abc123#key
```

### Send to a specific user (identity mode)

```bash
# Recipient must first generate and register a keypair
./sneaker init

# Send to their registered email
./sneaker send --to alice@example.com "secret for alice"
```

### Receive identity-mode secrets

```bash
./sneaker recv
# Retrieves and decrypts all pending secrets for your account
```

### Teams

```bash
# Create a team
./sneaker team create ops-team

# Generate an invite
./sneaker team invite ops-team
# Prints an invite token

# Join with invite
./sneaker team join <invite-token>

# Send to all team members
./sneaker send --to @ops-team "shared secret"
```

### Check secret status

```bash
./sneaker status <secret-id>
# Shows: pending/retrieved/expired, created_at, expires_at
```

## Architecture

```
CLI (cobra)  ──▶  HTTP API  ──▶  Store (SQLite)
                     │
Web Frontend  ───────┘
```

- **CLI commands** handle encryption/decryption using the AGE library
- **HTTP server** stores and serves encrypted ciphertext (never plaintext)
- **Web frontend** decrypts in the browser using JavaScript
- **SQLite** with WAL mode and dual connection pools (1 writer, 10 readers)

## Security

- Passwords hashed with **Argon2id** (RFC 9106 parameters)
- Session tokens: 32 random bytes, SHA-256 hashed before storage
- CSRF protection via **Fetch Metadata** headers
- Security headers: CSP, X-Frame-Options DENY, X-Content-Type-Options nosniff
- Database created with 0600 permissions
- Secret IDs are 256-bit random values (64 hex chars)
- Constant-time password verification to prevent user enumeration

**Important:** Sneaker does not handle TLS. Deploy behind a TLS-terminating reverse proxy (nginx, Caddy, etc.) for production use.

## Development

```bash
# Run with live frontend reload
go run . serve --dev

# Run tests
go test ./...

# Run tests with race detector
go test -race ./...

# Run tests with coverage
go test -cover ./...
```

## Requirements

- Go 1.25 or later
- No CGo required (uses pure-Go SQLite driver)

## License

All rights reserved.
