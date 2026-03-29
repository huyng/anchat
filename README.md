# AnChat

> A modern, secure, and easy-to-use alternative to IRC

**AnChat** is a real-time chat system that prioritizes privacy by design. The server never has access to plaintext messages—only encrypted blobs. Transport is TLS-only, stored data is encrypted at rest, and end-to-end encryption is default for private messages.

## Features

### Security First
- 🔒 **End-to-end encryption** by default using NaCl box (Curve25519 + ChaCha20-Poly1305)
- 🔐 **Argon2id password hashing** — memory-hard for modern hardware
- 🔑 **Ed25519/X25519 keypairs** — for signing and encryption
- 🔒 **At-rest encryption** — messages encrypted server-side with AES-256-GCM
- ✅ **Perfect forward secrecy** — TLS 1.3 prevents session key compromise
- 🛡️ **Blind indexes** — moderation without revealing user identities

### Ease of Use
- 💜 **Modern HTTP/2 API** — firewall-friendly, works with standard ports
- 🌐 **Native browser support** — Server-Sent Events (SSE) streaming
- 📱 **Mobile-first architecture** — designed for native mobile clients
- ⚡ **Low latency** — optimized for real-time messaging
- 🔍 **Searchable history** — clients can store and search messages locally (encrypted)
- 📦 **Single binary deployment** — no VM, no heavy runtime

### Open & Decentralized
- 📖 **Open protocol** — documented and extensible
- 🌐 **Federation-ready** — protocol designed for future server-to-server communication
- 🔓 **No single point of failure** — local encrypted storage on clients
- 👥 **Community-governed** — per-channel moderation tools

## Comparison: IRC vs AnChat

| Feature | IRC | AnChat |
|---|---|---|
| **Encryption** | TLS only (optional) | E2E by default (NaCl box) |
| **Onboarding** | Manual (`/nick`, `/join`, NickServ) | Click-and-go with public keys |
| **Rich media** | No (text only) | Yes (images, files, code snippets) |
| **Mobile UX** | Poor (terminal-based) | Native mobile apps (planned) |
| **Message history** | Client-side only | Encrypted server-side + local caching |
| **Identity** | Nicknames (easily impersonated) | Verified identities (Ed25519 signatures) |
| **Moderation** | Manual ops/chanserv | Automated + blind indexes |
| **Spam protection** | None (by design) | Rate limiting + CAPTCHA |

## Architecture

```
[CLI/Web/Mobile Client] --HTTP/2 POST--> [AnChat Server (Go)] --SSE--> [Client]
                                          |
                                [Encrypted at rest DB]
```

### Bidirectional Communication Strategy

| Direction | Protocol | Why |
|---|---|---|
| Client → Server | HTTP/2 POST (JSON) | Simple request-response, idempotent, works with any HTTP client |
| Server → Client | HTTP/2 SSE | Lightweight, one persistent connection, automatic reconnect |
| Optional upgrade | WebSocket (WSS) | For very high throughput or when server→client initiated messages are frequent |

**Default mode:** Client opens two connections:
- SSE connection (`GET /listen`) — receives incoming messages
- POST connection (`POST /command`) — sends commands

## Technology Stack

### Backend
- **Language:** Go 1.25+ (Golang)
- **Database:** SQLite with `github.com/mattn/go-sqlite3`
- **HTTP:** HTTP/2 with Server-Sent Events (SSE)
- **WebSocket:** Optional WebSocket upgrade path
- **Cryptography:**
  - `golang.org/x/crypto/nacl/box` — E2E encryption (Curve25519 + ChaCha20-Poly1305)
  - `golang.org/x/crypto/ed25519` — Signatures
  - `golang.org/x/crypto/argon2` — Password hashing (Argon2id)
  - `crypto/tls` — TLS 1.3 with perfect forward secrecy

### Frontend (Planned)
- **Desktop:** Tauri (Rust + web tech)
- **Mobile:** React Native or Flutter
- **Web:** SvelteKit or Next.js
- **CLI:** Go client with same crypto libraries

### Deployment
- **Binary:** Single static binary compiled from `cmd/server`
- **OS Support:** Linux, macOS, Windows (Go cross-compilation)
- **Runtime:** No external dependencies (embedded SQLite driver)

## Security Model

| Threat | Mitigation |
|---|---|
| Eavesdropper on network | TLS 1.3 + perfect forward secrecy |
| Server operator reads stored messages | At-rest encryption (AES-256-GCM) + E2E for PMs |
| Server operator reads live messages | Cannot — only encrypted blobs pass through |
| Compromised server DB | Blobs useless without user private keys (stored only on clients) |
| MITM during key exchange | Out-of-band verification (fingerprint compare, like Signal) |
| Replay attacks | Unique nonce per message, server rejects duplicates |
| Spam / abuse | Rate limiting + CAPTCHA + per-channel moderation keys |

**Important trade-off:** The server cannot search messages or provide read receipts. To restore usability, clients implement local search and store message history locally (encrypted).

## API Overview

### Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v1/auth` | POST | User authentication |
| `/api/v1/listen` | GET | SSE event stream |
| `/api/v1/command` | POST | Send single command |
| `/api/v1/command/batch` | POST | Send multiple commands |
| `/api/v1/websocket` | GET | WebSocket upgrade (optional) |
| `/health` | GET | Health check |

### Commands

- `auth` — User authentication
- `bot_auth` — Bot authentication
- `msg` — Private messages
- `channel_create` — Create channels
- `channel_join` — Join channels
- `channel_send` — Channel messages
- `channel_invite` — Invite users
- `history_sync` — Request message history
- `status` — Update user status
- `logout` — Terminate session

### Events (SSE)

- `message` — Private message
- `channel_message` — Channel message
- `user_joined` — User joined channel
- `user_left` — User left channel
- `error` — Error notification

## Documentation

- **[PROTOCOL.md](PROTOCOL.md)** — Complete protocol specification with all commands, events, and examples
- **[GETTING_STARTED.md](GETTING_STARTED.md)** — Step-by-step setup and development guide

## Roadmap

### Phase 1: MVP (Core Chat) — ✅ Complete
- [x] Basic server and client
- [x] Channel creation and joining
- [x] Real-time messaging via SSE
- [x] Basic user authentication
- [x] TLS encryption

### Phase 2: Security — 🚧 In Progress
- [ ] E2E encryption implementation (crypto library ready)
- [ ] Key exchange (X3DH or manual)
- [ ] Double ratchet for forward secrecy
- [ ] Identity verification

### Phase 3: Modern Features — 📝 Planned
- [ ] Rich media support
- [ ] Message history (encrypted server-side)
- [ ] Search functionality
- [ ] User profiles
- [ ] Emoji reactions

### Phase 4: Federation — 📝 Planned
- [ ] Server federation protocol
- [ ] Server discovery
- [ ] Cross-server channels
- [ ] Moderation tools

### Phase 5: Ecosystem — 📝 Planned
- [ ] Bot API
- [ ] Plugin system
- [ ] REST API
- [ ] Mobile apps (iOS/Android)

## Building

### Prerequisites
- Go 1.25 or later
- Git
- TLS certificate (for production deployment)

### Build Server

```bash
git clone https://github.com/huyng/anchat.git
cd anchat
go build -o anchat-server ./cmd/server
```

### Run Server (Development)

```bash
# Generate storage key
head -c 32 /dev/urandom | base64 > server_storage.key

# Run with SQLite
export ANCHAT_DB_URL="anchat.db"
export ANCHAT_STORAGE_KEY=$(cat server_storage.key)
./anchat-server --port 8443
```

### Run Server (Production)

```bash
# Required arguments
./anchat-server \
  --db /var/lib/anchat/anchat.db \
  --storage-key /etc/anchat/storage.key \
  --cert /etc/ssl/fullchain.pem \
  --key /etc/ssl/privkey.pem \
  --port 443
```

## Contributing

This project is in early development. We welcome contributions once the initial features are implemented and tested.

## License

MIT License

---

**Built with 💜 for the future of open, secure chat.**

For more details, see:
- **[PROTOCOL.md](PROTOCOL.md)** — Complete protocol documentation
- **[GETTING_STARTED.md](GETTING_STARTED.md)** — Development guide
