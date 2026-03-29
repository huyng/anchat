# Getting Started with AnChat

This guide walks you through setting up, running, and developing AnChat.

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/huyng/anchat.git
cd anchat
```

### 2. Install Go (if not installed)

**Linux:**
```bash
wget https://go.dev/dl/go1.22.2.linux-amd64.tar.gz
tar -C $HOME/.local -xzf go1.22.2.linux-amd64.tar.gz
export PATH="$HOME/.local/go/bin:$PATH"
export GOROOT="$HOME/.local/go"
```

**macOS:**
```bash
brew install go
```

**Windows:**
Download from https://go.dev/dl/ and follow installer instructions.

Verify installation:
```bash
go version  # Should be 1.22.2 or later
```

### 3. Build the Server

```bash
# From the anchat directory
go build -o anchat-server ./cmd/server
```

This creates the `anchat-server` binary in the current directory.

### 4. Generate Storage Key

The server needs a key for at-rest encryption:

```bash
# Generate 32-byte random key
head -c 32 /dev/urandom | base64 > server_storage.key
```

**⚠️ Important:** Keep this key secure! If lost, stored messages cannot be decrypted.

### 5. Generate TLS Certificates (for production)

**Development (self-signed):**
```bash
# Create self-signed cert for testing
openssl req -x509 -newkey rsa:4096 -keyout privkey.pem -out fullchain.pem -days 365 -nodes -subj "/CN=localhost"
```

**Production (Let's Encrypt):**
```bash
# Use certbot to get free TLS certificates
sudo certbot certonly --standalone -d chat.example.com
# Certs will be in /etc/letsencrypt/live/chat.example.com/
```

### 6. Run the Server

**Development mode (HTTP, no TLS):**
```bash
export ANCHAT_DB_URL="anchat.db"
export ANCHAT_STORAGE_KEY=$(cat server_storage.key)
./anchat-server --port 8443
```

**Production mode (HTTPS with TLS):**
```bash
export ANCHAT_DB_URL="/var/lib/anchat/anchat.db"
export ANCHAT_STORAGE_KEY=$(cat /etc/anchat/storage.key)
export ANCHAT_TLS_CERT="/etc/ssl/fullchain.pem"
export ANCHAT_TLS_KEY="/etc/ssl/privkey.pem"
./anchat-server --port 443
```

**Check server is running:**
```bash
curl http://localhost:8443/health
# Should return: {"status":"ok","time":"2026-03-29T..."}
```

## Development Guide

### Project Structure

```
anchat/
├── cmd/
│   └── server/
│       └── main.go          # Server entry point
├── internal/
│   ├── auth/                # Authentication logic
│   │   └── auth.go
│   ├── crypto/               # Cryptography operations
│   │   └── crypto.go
│   ├── db/                   # Database layer
│   │   └── db.go
│   ├── models/               # Data models
│   │   ├── channel.go
│   │   ├── message.go
│   │   └── user.go
│   ├── protocol/             # Protocol handlers
│   │   └── server.go
│   └── server/               # HTTP/2 server
│       └── server.go
├── pkg/
│   └── protocol/            # Protocol definitions
│       └── messages.go
├── PROTOCOL.md             # Protocol specification
├── README.md               # This file
└── go.mod                 # Go module definition
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with verbose output
go test -v ./...
```

### Database Schema

The SQLite database is automatically initialized on first run:

```sql
-- Users table
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    username_hash BLOB NOT NULL,
    pubkey_ed25519 BLOB NOT NULL,
    pubkey_x25519 BLOB NOT NULL,
    password_hash BLOB NOT NULL,
    session_token_hash BLOB,
    created_at INTEGER NOT NULL
);

-- Channels table
CREATE TABLE channels (
    channel_id TEXT PRIMARY KEY,
    name_hash BLOB NOT NULL,
    member_count INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL
);

-- Channel members
CREATE TABLE channel_members (
    channel_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    joined_at INTEGER NOT NULL,
    is_op INTEGER DEFAULT 0,
    PRIMARY KEY (channel_id, user_id)
);

-- Messages table
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id TEXT,
    recipient_user_id TEXT,
    sender_key_hash BLOB NOT NULL,
    encrypted_blob BLOB NOT NULL,
    signature BLOB NOT NULL,
    timestamp INTEGER NOT NULL
);
```

### API Usage Examples

#### Authentication

```bash
curl -X POST http://localhost:8443/api/v1/auth \
  -H "Content-Type: application/json" \
  -d '{
    "cmd": "auth",
    "user": "alice",
    "password": "base64_password_proof",
    "pubkey_ed25519": "base64_encoded_pubkey",
    "pubkey_x25519": "base64_encoded_pubkey"
  }'
```

Response:
```json
{
  "status": "ok",
  "session_token": "eyJhbGc...",
  "user_id": "alice_abc123"
}
```

#### Listen to Events (SSE)

```bash
curl -N http://localhost:8443/api/v1/listen \
  -H "Authorization: Bearer eyJhbGc..."
```

This will stream events in real-time:
```
event: connected
data: {"user_id":"alice_abc123"}

event: message
data: {"type":"private","from":"bob","ciphertext":"base64...","nonce":"base64..."}
```

#### Send a Command

```bash
curl -X POST http://localhost:8443/api/v1/command \
  -H "Authorization: Bearer eyJhbGc..." \
  -H "Content-Type: application/json" \
  -d '{
    "cmd": "status",
    "state": "online"
  }'
```

## Building a Client

### Minimal CLI Client Example (Go)

```go
package main

import (
    "encoding/json"
    "log"
    "net/http"

    "github.com/huyng/anchat/pkg/protocol"
)

func main() {
    // 1. Authenticate
    resp, err := http.Post("http://localhost:8443/api/v1/auth", "application/json", bytes.NewReader(authJSON))
    if err != nil {
        log.Fatal(err)
    }

    var authResp protocol.AuthResponse
    json.NewDecoder(resp.Body).Decode(&authResp)
    sessionToken := authResp.SessionToken

    // 2. Connect to SSE stream
    req, _ := http.NewRequest("GET", "http://localhost:8443/api/v1/listen", nil)
    req.Header.Set("Authorization", "Bearer "+sessionToken)

    client := &http.Client{}
    sseResp, err := client.Do(req)
    if err != nil {
        log.Fatal(err)
    }

    // 3. Read events
    decoder := json.NewDecoder(sseResp.Body)
    for {
        var event map[string]interface{}
        if err := decoder.Decode(&event); err != nil {
            break
        }
        log.Printf("Event: %v", event)
    }
}
```

### Web Client Example (JavaScript)

```javascript
// 1. Authenticate
async function login(username, password, pubkeys) {
  const resp = await fetch('/api/v1/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      cmd: 'auth',
      user: username,
      password: password,
      pubkey_ed25519: pubkeys.ed25519,
      pubkey_x25519: pubkeys.x25519
    })
  });
  return await resp.json();
}

// 2. Connect to SSE stream
function connectEvents(sessionToken) {
  const eventSource = new EventSource('/api/v1/listen');

  eventSource.addEventListener('message', (event) => {
    const data = JSON.parse(event.data);
    console.log('Received:', data);
  });

  eventSource.addEventListener('error', (error) => {
    console.error('SSE error:', error);
  });
}

// 3. Send command
async function sendCommand(sessionToken, command) {
  await fetch('/api/v1/command', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${sessionToken}`
    },
    body: JSON.stringify(command)
  });
}
```

## Development Workflow

### Adding New Commands

1. **Define command in protocol:**
   ```go
   // pkg/protocol/messages.go
   const CmdMyNewCommand CommandType = "my_new_command"
   type MyNewCommand struct {
       Cmd     CommandType `json:"cmd"`
       Field1  string     `json:"field1"`
       Field2  int        `json:"field2"`
   }
   ```

2. **Add handler in server:**
   ```go
   // internal/server/server.go
   func (s *Server) handleMyNewCommand(ctx context.Context, userID string, cmdData map[string]interface{}) protocol.CommandResponse {
       // Parse and validate
       // Execute logic
       // Return response
   }
   ```

3. **Register in switch statement:**
   ```go
   // internal/server/server.go - handleCommandByType
   switch protocol.CommandType(cmdType) {
   case CmdMyNewCommand:
       return s.handleMyNewCommand(ctx, userID, cmdData)
   // ... other cases
   }
   ```

### Adding New Events

1. **Define event type:**
   ```go
   // pkg/protocol/messages.go
   const EventMyNewEvent SSEEventType = "my_new_event"
   type MyNewEvent struct {
       Type      string `json:"type"`
       Field1    string `json:"field1"`
       Field2    int    `json:"field2"`
       Timestamp  int64  `json:"timestamp"`
   }
   ```

2. **Send event to subscribers:**
   ```go
   // internal/server/server.go
   func (s *Server) notifyUser(userID string, event interface{}) {
       s.mu.RLock()
       defer s.mu.RUnlock()

       if ch, ok := s.subscribers[userID]; ok {
           eventData, _ := json.Marshal(event)
           ch <- eventData
       }
   }
   ```

### Database Migrations

To add a new table or modify existing schema:

1. Update schema in `internal/db/db.go`:
   ```go
   // Add new table to initSchema()
   ALTER TABLE ... or CREATE TABLE ...
   ```

2. Add CRUD methods:
   ```go
   func (db *DB) CreateMyNewThing(ctx context.Context, thing *models.MyNewThing) error {
       query := `INSERT INTO my_new_things (...) VALUES (?, ...)`
       _, err := db.ExecContext(ctx, query, ...)
       return err
   }
   ```

## Cryptography Guide

### Generating Key Pairs

```go
import "github.com/huyng/anchat/internal/crypto"

// Ed25519 keypair (for signatures)
keypair, err := crypto.GenerateKeyPair()
// keypair.PrivateKey — Ed25519 private key
// keypair.PublicKey — Ed25519 public key

// X25519 keypair (for encryption)
encKeypair, err := crypto.GenerateEncryptionKeyPair()
// encKeypair.PrivateKey — X25519 private key
// encKeypair.PublicKey — X25519 public key
```

### Encrypting Messages

```go
// Get recipient's X25519 public key
recipientPubKey := getRecipientPublicKey() // [32]byte

// My X25519 private key
myPrivKey := getMyPrivateKey() // [32]byte

// Generate nonce
nonce, err := crypto.GenerateNonce()

// Encrypt
ciphertext, err := crypto.BoxEncrypt([]byte("Hello!"), nonce, &recipientPubKey, &myPrivKey)
```

### Signing Messages

```go
// Message content
message := []byte("Hello!")

// My Ed25519 private key
myPrivKey := getMySigningPrivateKey()

// Sign
signature := crypto.Sign(message, myPrivKey)
```

### Password Hashing

```go
import "github.com/huyng/anchat/internal/crypto"

// Generate salt
salt, err := crypto.GenerateSalt()

// Hash password (Argon2id)
hash, err := crypto.HashPassword("mypassword", salt)
```

## Troubleshooting

### Common Issues

**"command not found: go"**
- Install Go: https://go.dev/dl/
- Add to PATH: `export PATH="$HOME/.local/go/bin:$PATH"`

**"dial tcp: connection refused"**
- Check server is running: `curl localhost:8443/health`
- Verify port: `lsof -i :8443` (Linux) or `lsof -i :8443` (macOS)

**"TLS handshake error"**
- Verify certificate paths exist and are readable
- Check certificate is valid: `openssl x509 -in fullchain.pem -text -noout`

**"database locked"**
- Another process has the database file open
- Check: `lsof anchat.db`
- Stop other instances

### Debug Mode

Enable verbose logging:

```bash
# Set log level environment variable
export LOG_LEVEL=debug

./anchat-server --port 8443
```

## Next Steps

1. **Implement stubbed handlers** — Complete E2E message routing and channel operations
2. **Build CLI client** — Create a reference implementation
3. **Add tests** — Unit tests for crypto, integration tests for server
4. **Deploy** — Set up production TLS certificates and run on port 443
5. **Build web UI** — Create a browser-based client

## Resources

- **[PROTOCOL.md](PROTOCOL.md)** — Complete protocol specification
- **[README.md](README.md)** — Project overview and architecture
- **Go Documentation** — https://golang.org/doc/
- **NaCl Crypto** — https://nacl.cr.yp.to/

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/huyng/anchat/issues
- GitHub PRs: https://github.com/huyng/anchat/pulls

---

**Happy coding! 💜**
