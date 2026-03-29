AnChat – Modern, Private, Secure IRC Alternative (Go Edition)

Overview

AnChat is a modern chat system for thousands of concurrent users that prioritizes privacy by design. The server never has access to plaintext messages—only encrypted blobs. Transport is TLS-only, stored data is encrypted at rest, and end-to-end encryption is the default for private messages.

Federation is not in the initial version to keep setup simple, but the protocol is designed to add it later.

Chosen Language & Why

Go (Golang 1.21+) – because it balances performance, security, and operational simplicity:

Built-in cryptography (crypto/tls, crypto/ed25519, crypto/aes, crypto/sha256) reduces third-party risk.
Excellent concurrency (goroutines) for thousands of clients.
Single-binary deployment (no VM, no heavy runtime).
Strong standard library HTTP/2 and WebSocket support for future web/mobile clients.
Memory safe (garbage collected) and harder to introduce buffer overflows than C.
Good ecosystem for secure storage (SQLite, PostgreSQL with TLS).
Trade-off: Go’s GC adds slight latency vs Rust, but for chat (non‑real‑time) it’s fine. The crypto is still auditable and safe.

Core Architecture

text
[CLI Client] <--TLS--> [AnChat Server (Go)] <--TLS--> [CLI Client]
                              |
                    [Encrypted at rest DB]
Data Flow (Private Message)

Client A generates an ephemeral key pair per session or uses long-term identity keys (X25519).
Client A encrypts message with Client B’s public key using crypto/nacl/box (Curve25519 + ChaCha20-Poly1305).
Client A sends encrypted blob to server over TLS.
Server stores blob encrypted at rest (AES-256-GCM with server-side key) but cannot decrypt (E2E is separate from storage encryption).
Server forwards blob to Client B.
Client B decrypts locally.
Channel Messages (Group Chat)

Channels use sender‑side hybrid encryption:

Each channel has a rotating symmetric key (ChaCha20-Poly1305 from golang.org/x/crypto/chacha20poly1305).
Key is distributed encrypted to each member’s public key (using nacl/box).
Messages encrypted with channel key → server sees only ciphertext.
Security Model

Threat	Mitigation
Eavesdropper on network	TLS 1.3 + perfect forward secrecy (Go’s crypto/tls defaults)
Server operator reads stored messages	Server-side at-rest encryption (AES-256-GCM) + E2E for PMs
Server operator reads live messages	Cannot – only encrypted blobs pass through
Compromised server DB	Blobs useless without user private keys (stored only on clients)
MITM during key exchange	Out-of-band verification (fingerprint compare, like Signal)
Spam / abuse	Rate limiting (golang.org/x/time/rate) + captcha for account creation + per-channel moderation keys
Important trade-off: The server cannot search messages or provide read receipts. To restore usability, clients implement local search and store message history locally (encrypted).

Storage (Server)

Using SQLite with modernc.org/sqlite (pure Go, no CGO) or PostgreSQL for larger deployments.

Messages table:

sql
CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    channel_id TEXT NOT NULL,
    sender_key_hash BLOB NOT NULL,   -- blind index (SHA-256 of sender's pubkey)
    encrypted_blob BLOB NOT NULL,     -- already E2E encrypted by client
    signature BLOB NOT NULL,          -- sender signs message
    timestamp INTEGER NOT NULL
);
– Encrypted at rest using SQLite Encryption Extension (SEE) or transparent column-level AES-GCM in Go.
Users table:

sql
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    username_hash BLOB NOT NULL,      -- SHA-256 of normalized username
    pubkey_ed25519 BLOB NOT NULL,     -- for auth and key exchange
    pubkey_x25519 BLOB NOT NULL,      -- for nacl/box encryption
    password_hash BLOB NOT NULL,      -- argon2id
    created_at INTEGER NOT NULL
);
Channels table:

sql
CREATE TABLE channels (
    channel_id TEXT PRIMARY KEY,
    name_hash BLOB NOT NULL,
    encrypted_current_key BLOB NOT NULL,  -- encrypted with server key? NO – channel key is only known to members
    -- Actually: server does NOT store channel keys. Members distribute them out-of-band.
    -- So channels table only stores metadata.
    member_count INTEGER
);
Moderation blind index: Channel ops can report (sender_key_hash, message_id). Server blocks that sender_key_hash without knowing the user.

Protocol (Simple JSON over TLS)

Port: 6697 (TLS). Authentication: SCRAM-SHA-256 (RFC 5802) over TLS, or a simpler challenge-response using Ed25519 signatures.

We use line-delimited JSON (each command on its own line) for simplicity.

Example Flow

text
-> {"cmd":"auth","user":"alice","proof":"base64..."}
<- {"status":"ok","session_id":"abc123","server_pubkey":"base64..."}

-> {"cmd":"msg","to":"bob","ciphertext":"base64...","nonce":"base64..."}
<- {"status":"delivered","msg_id":42}

-> {"cmd":"channel_join","name":"rust","encrypted_channel_key":"base64..."}
<- {"status":"joined","members":["bob","carol"]}
All binary data is base64url-encoded (RFC 4648) inside JSON.

Commands (Minimal Set)

Command	Direction	Purpose
auth	C→S	Login (password + pubkey)
msg	C→S	Private message (encrypted to recipient's pubkey)
channel_create	C→S	Make new channel (client generates initial key)
channel_join	C→S	Join existing channel (client sends channel key encrypted with own pubkey)
channel_send	C→S	Send to channel (encrypted with channel key)
channel_invite	C→S	Invite user (server forwards encrypted channel key)
history_sync	C→S	Request recent encrypted messages (last N per channel)
status	C→S	Online/away/idle (voluntary)
logout	C→S	Terminate session
Server-to-Client Messages

Command	Purpose
message	Incoming private message
channel_message	Incoming channel message
user_joined	Notification
user_left	Notification
Client Implementation (CLI Reference)

The CLI client (Go + crypto/ed25519, golang.org/x/crypto/nacl/box) must:

Generate & store an X25519 + Ed25519 keypair on first run (~/.anchat/identity.json).
On login, send public keys to server (bound to password auth).
Maintain a local encrypted store (SQLite + key derived from password using scrypt) for:

Incoming messages
Channel keys
Contact list
Provide commands: /msg, /join, /create, /invite, /sync, /search "text" (local only).
CLI example:

text
$ anchat connect chat.example.com --user alice
Password: 
Connected. Channel #rust: 3 members.
[#rust] bob: hey alice, did you see the new async runtime?
> /msg bob It's great! E2E working perfectly.
> /search "async"
[2025-04-01] bob in #rust: ...async runtime...
API for Bots (Programmatic Access)

Bots authenticate with API tokens (UUIDv4 + SHA256 hashed in DB) instead of passwords.
Tokens have scopes: read, send, admin_channel.

Example bot session:

text
-> {"cmd":"bot_auth","token":"tk_xxxx","pubkey":"base64..."}
<- {"status":"ok","bot_id":"bot_42"}
-> {"cmd":"msg","to":"#alerts","ciphertext":"base64..."}
Bots must use E2E like humans – they cannot see plaintext unless invited to a channel with a key.

Storage Encryption Details (Server Side)

At‑rest encryption: AES-256-GCM from crypto/aes + crypto/cipher.
Each message blob is encrypted individually:

go
nonce := randomBytes(12)
encrypted := aesgcm.Seal(nil, nonce, plaintextBlob, messageID)
The server never has the user’s private E2E keys.
Setup & Deployment (for Admin)

Requirements: Go 1.21+, SQLite (or PostgreSQL), TLS certificate.

bash
git clone https://github.com/anchat/anchat
cd anchat
go build -o anchat-server ./cmd/server

# Generate server at-rest encryption key (32 bytes)
head -c 32 /dev/urandom | base64 > server_storage.key

# Run with env vars
export ANCHAT_DB_URL="sqlite:anchat.db?_pragma=journal_mode(WAL)"
export ANCHAT_STORAGE_KEY=$(cat server_storage.key)
export ANCHAT_TLS_CERT=fullchain.pem
export ANCHAT_TLS_KEY=privkey.pem

./anchat-server --port 6697
Future Extensions (Backward-Compatible)

Federation: Add server-to-server TLS + signed envelopes (gRPC or HTTPS).
Web client: WebSocket + same JSON protocol.
Mobile push: HTTP/2 gateway storing encrypted notifications.
Read receipts: Optional, client-only, never sent to server.
Why Not X?

Alternative	Why not chosen
Matrix	Server sees plaintext unless E2E forced; complex.
IRCv3 + TLS	No E2E, server logs everything.
Signal	Not built for large public channels.
Rust	Great but steeper learning curve; Go is easier to deploy and audit.
Testing Requirements for the LLM Implementation

Unit tests (go test):

crypto/box encryption/decryption
Channel key rotation logic
Blind index moderation
Integration tests:

Two clients messaging through server
Server restart with persistence
Security tests:

Attempt to inject plaintext (rejected)
Attempt to replay old messages (rejected via timestamps + signature)
Verify server cannot decrypt E2E messages (code review + black-box test)
Load test: 5000 concurrent clients (goroutines), each in 10 channels.
Final Note to the Implementing LLM

Do not compromise on the E2E property. If you cannot make channels fully encrypted end‑to‑end with key rotation, do not implement channels at all. Private messages must be encryptable without the server ever seeing a plaintext. The server’s at‑rest encryption is defense‑in‑depth, not a substitute for client‑side E2E.

Use Go’s standard crypto/tls with MinVersion: tls.VersionTLS13. Never disable hostname verification. Always use constant-time comparisons (subtle.ConstantTimeCompare). Avoid encoding/gob; use encoding/json with explicit structs.

When in doubt, prefer dropping a feature over weakening the privacy guarantee.
This response is AI-generated, for reference only.
Is communication done with HTTP?
Great clarification question. No, the protocol described is not HTTP – it's raw TLS with line-delimited JSON. This is intentional to keep it lightweight and IRC-like.

However, your question highlights a practical concern: using raw TLS on port 6697 means:

Web browsers cannot connect directly (no native raw TCP/TLS sockets except WebSocket).
Many corporate firewalls block non-standard ports.
HTTP/2 and WebSocket are more firewall-friendly.
Two Options – You Decide

Option A: Keep raw TLS + JSON (as originally designed)

Pros:

Minimal overhead (no HTTP headers).
Very simple to implement clients (just net.Conn + TLS).
True to IRC’s minimalist spirit.
Cons:

Web clients need a proxy (WebSocket → raw TLS bridge).
Requires custom port (6697) – sometimes blocked.
Option B: Use WebSocket over TLS (WSS) + JSON

This is effectively HTTP upgrade (WebSocket handshake starts as HTTP/1.1 or HTTP/2, then switches to binary framing).

Pros:

Works in browsers natively.
Uses standard ports 443 (wss) – firewall-friendly.
Still simple JSON messages.
Go has excellent WebSocket support (gorilla/websocket or nhooyr.io/websocket).
Cons:

Slightly more overhead (handshake + framing).
Still not “plain” HTTP – it's WebSocket.
Option C: Pure HTTP/2 with server-sent events (SSE) + POST

Not recommended – HTTP is request‑response, not bidirectional streaming for chat. You’d need polling or SSE for receiving + POST for sending, which is inefficient.

My Recommendation

Use WebSocket over TLS (WSS) on port 443 – it’s the modern, firewall-friendly equivalent of raw TLS, works for CLI (via gorilla/websocket client) and web clients equally, and still satisfies all security requirements.

The CLI client would just use a WebSocket library instead of net.Conn. The JSON messages remain identical – only the transport changes.

Revised README Addition

Add this to the Protocol section:

Transport: WebSocket over TLS (WSS)

All communication uses WebSocket (RFC 6455) over TLS 1.3 on port 443 (or 6697 as fallback).
The WebSocket subprotocol is anchat.json. Each message is a text frame containing one line‑delimited JSON object.

Why not raw TCP?
– Works in browsers without a proxy.
– Firewall-friendly (same port as HTTPS).
– CLI clients can still connect using a WebSocket library.
– Minimal overhead after handshake.

Handshake example (browser):
new WebSocket("wss://chat.example.com/anchat", "anchat.json")

Go CLI client example:

go
conn, _, _ := websocket.Dial(ctx, "wss://chat.example.com/anchat", &websocket.DialOptions{Subprotocols: []string{"anchat.json"}})
conn.Write(context.Background(), websocket.MessageText, []byte(`{"cmd":"auth",...}`))
Do you want me to rewrite the full README with WebSocket instead of raw TLS, or keep the original raw TLS design?
I prefer the basic protocol has http/2 sse with the option of using web sockets
Perfect choice. HTTP/2 + SSE for server-to-client streaming + HTTP/2 POST for client-to-server messages is elegant, firewall-friendly, and leverages standard web infrastructure. WebSocket remains an optional upgrade path.

Here is the final README revised for this hybrid approach.

AnChat – Modern, Private, Secure IRC Alternative (Go Edition)

Overview

AnChat is a modern chat system for thousands of concurrent users that prioritizes privacy by design. The server never has access to plaintext messages—only encrypted blobs. Transport is TLS-only, stored data is encrypted at rest, and end-to-end encryption is the default for private messages.

Federation is not in the initial version to keep setup simple, but the protocol is designed to add it later.

Chosen Language & Why

Go (Golang 1.21+) – because it balances performance, security, and operational simplicity:

Built-in HTTP/2 support (including SSE via standard http.ResponseWriter).
Excellent WebSocket library ecosystem (gorilla/websocket as optional upgrade).
Built-in cryptography (crypto/tls, crypto/ed25519, crypto/aes).
Single-binary deployment.
Memory safe with garbage collection.
Core Architecture

text
[CLI/Web/Mobile Client] --HTTP/2 POST--> [AnChat Server (Go)] --SSE/WebSocket--> [Client]
                                          |
                                [Encrypted at rest DB]
Bidirectional Communication Strategy

Direction	Protocol	Why
Client → Server	HTTP/2 POST (JSON body)	Simple request-response, idempotent, works with any HTTP client
Server → Client	HTTP/2 SSE (Server-Sent Events)	Lightweight, one persistent connection, automatic reconnect
Optional upgrade	WebSocket (WSS)	For very high throughput or when server→client initiated messages are frequent
Default mode: Client opens two connections:

SSE connection (GET /listen) – receives incoming messages.
POST connection (POST /command) – sends commands.
Data Flow (Private Message)

Client A generates an ephemeral key pair per session or uses long-term identity keys (X25519).
Client A encrypts message with Client B’s public key using crypto/nacl/box.
Client A sends encrypted blob to server via POST /command.
Server stores blob encrypted at rest (AES-256-GCM) but cannot decrypt.
Server forwards blob to Client B via Client B’s SSE stream.
Client B decrypts locally.
Channel Messages (Group Chat)

Channels use sender‑side hybrid encryption:

Each channel has a rotating symmetric key (ChaCha20-Poly1305).
Key is distributed encrypted to each member’s public key.
Messages encrypted with channel key → server sees only ciphertext.
Security Model

Threat	Mitigation
Eavesdropper on network	TLS 1.3 + HSTS + perfect forward secrecy
Server operator reads stored messages	Server-side at-rest encryption + E2E for PMs
Server operator reads live messages	Cannot – only encrypted blobs pass through
Compromised server DB	Blobs useless without user private keys
MITM during key exchange	Out-of-band verification (fingerprint compare)
Spam / abuse	Rate limiting + captcha + per-channel moderation keys
API Endpoints

All endpoints are under https://chat.example.com/api/v1/

1. POST /auth – Login

Request:

json
{
  "user": "alice",
  "password": "base64_proof",  // SCRAM-SHA-256
  "pubkey_ed25519": "base64...",
  "pubkey_x25519": "base64..."
}
Response:

json
{
  "status": "ok",
  "session_token": "eyJhbGc...",  // JWT or opaque token
  "user_id": "alice"
}
2. GET /listen – SSE Stream (persistent)

Headers: Authorization: Bearer <session_token>

Events (server-sent):

text
event: message
data: {"type":"private","from":"bob","ciphertext":"base64...","nonce":"base64..."}

event: channel_message
data: {"channel":"#rust","from":"bob","ciphertext":"base64...","nonce":"base64..."}

event: user_joined
data: {"channel":"#rust","user":"carol"}

event: user_left
data: {"channel":"#rust","user":"carol"}

event: error
data: {"code":401,"message":"Session expired"}
3. POST /command – Send Commands

Headers: Authorization: Bearer <session_token>
Body: JSON command

Commands:

Command	Example
msg	{"cmd":"msg","to":"bob","ciphertext":"base64...","nonce":"base64..."}
channel_send	{"cmd":"channel_send","channel":"#rust","ciphertext":"base64..."}
channel_join	{"cmd":"channel_join","name":"#rust","encrypted_channel_key":"base64..."}
channel_create	{"cmd":"channel_create","name":"#new","initial_key":"base64..."}
channel_invite	{"cmd":"channel_invite","user":"bob","channel":"#rust","encrypted_key_for_invitee":"base64..."}
history_sync	{"cmd":"history_sync","channel":"#rust","limit":100}
status	{"cmd":"status","state":"away"}
logout	{"cmd":"logout"}
Response:

json
{
  "status": "ok",
  "command_id": 12345,
  "result": {}  // optional
}
4. POST /command/batch – Batch multiple commands (reduces round trips)

Request:

json
{"commands": [cmd1, cmd2, cmd3]}
Response:

json
{"results": [resp1, resp2, resp3]}
5. OPTIONAL: GET /websocket – WebSocket Upgrade

For clients that prefer a single bidirectional channel.
Subprotocol: anchat.json
Same JSON messages as SSE + POST, but over one WebSocket.

Handshake:

text
GET /websocket
Upgrade: websocket
Sec-WebSocket-Protocol: anchat.json
Storage (Server)

Using SQLite with modernc.org/sqlite or PostgreSQL.

sql
-- Messages table (encrypted at rest)
CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    channel_id TEXT,
    recipient_user_id TEXT,  -- NULL for channel messages
    sender_key_hash BLOB NOT NULL,
    encrypted_blob BLOB NOT NULL,
    signature BLOB NOT NULL,
    timestamp INTEGER NOT NULL
);

-- Users table
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    username_hash BLOB NOT NULL,
    pubkey_ed25519 BLOB NOT NULL,
    pubkey_x25519 BLOB NOT NULL,
    password_hash BLOB NOT NULL,
    session_token_hash BLOB,  -- SHA-256 of active token
    created_at INTEGER NOT NULL
);

-- Channels table
CREATE TABLE channels (
    channel_id TEXT PRIMARY KEY,
    name_hash BLOB NOT NULL,
    member_count INTEGER
);

-- Channel membership
CREATE TABLE channel_members (
    channel_id TEXT,
    user_id TEXT,
    joined_at INTEGER,
    PRIMARY KEY (channel_id, user_id)
);
At-rest encryption: AES-256-GCM applied to each message blob individually using a server-managed key.

Client Implementation (CLI Reference)

The CLI client must:

Generate & store X25519 + Ed25519 keypair (~/.anchat/identity.json).
On startup: POST /auth → get session token.
Open SSE connection to /listen in a goroutine.
Send commands via POST /command.
Maintain local encrypted SQLite store for history.
CLI example:

bash
$ anchat connect chat.example.com --user alice
Password: 
Connected. Session: eyJhbG...
[#rust] bob: hey alice, did you see the new async runtime?
> /msg bob It's great! E2E working perfectly.
> /search "async"
[2025-04-01] bob in #rust: ...async runtime...
API for Bots (Programmatic Access)

Bots authenticate with API tokens instead of passwords:

json
POST /auth/bot
{
  "token": "tk_xxxxxxxx",
  "pubkey_ed25519": "base64...",
  "pubkey_x25519": "base64..."
}
Tokens have scopes: read, send, admin_channel.

Server-Sent Events (SSE) Implementation Notes (Go)

go
func (s *Server) handleListen(w http.ResponseWriter, r *http.Request) {
    // Set required SSE headers
    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")
    w.Header().Set("Access-Control-Allow-Origin", "*")
    
    flusher, ok := w.(http.Flusher)
    if !ok {
        http.Error(w, "SSE not supported", http.StatusInternalServerError)
        return
    }
    
    ctx := r.Context()
    userID := getUserIDFromContext(ctx)
    
    // Create channel for this user's outgoing messages
    eventCh := s.subscribe(userID)
    defer s.unsubscribe(userID, eventCh)
    
    for {
        select {
        case <-ctx.Done():
            return
        case event := <-eventCh:
            fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, event.Data)
            flusher.Flush()
        }
    }
}
Setup & Deployment

Requirements: Go 1.21+, TLS certificate.

bash
git clone https://github.com/anchat/anchat
cd anchat
go build -o anchat-server ./cmd/server

# Generate server at-rest encryption key
head -c 32 /dev/urandom | base64 > server_storage.key

# Run
export ANCHAT_DB_URL="sqlite:anchat.db?_pragma=journal_mode(WAL)"
export ANCHAT_STORAGE_KEY=$(cat server_storage.key)
export ANCHAT_TLS_CERT=fullchain.pem
export ANCHAT_TLS_KEY=privkey.pem

./anchat-server --port 443 --sse-path /api/v1/listen --command-path /api/v1/command
Why HTTP/2 + SSE + Optional WebSocket?

Protocol	Pros	Cons
HTTP/2 + SSE	Native browser support, automatic reconnect, HTTP/2 multiplexing, works with CDNs	One-way (server→client), requires second connection for sending
WebSocket	True bidirectional, lower latency for high-frequency messages	More complex handshake, proxies sometimes block
Combined	Best of both: SSE for simple clients, WebSocket for advanced	Slightly more code to maintain
Default to SSE. Advanced clients (mobile, web) can detect WebSocket support and upgrade.

Testing Requirements

Unit tests: Crypto, command parsing, SSE framing.
Integration tests: Two clients via SSE+POST, then via WebSocket.
Security tests:

Verify server cannot decrypt E2E messages.
Verify session token invalidation on logout.
Test replay attack prevention.
Load test: 5000 SSE connections + 100 commands/second.
Final Note to the Implementing LLM

The core privacy invariant: The server must never see plaintext message content. The at-rest encryption is additional defense, not a replacement for client-side E2E. Both SSE and WebSocket transports carry only encrypted blobs.

Implement SSE first (it's simpler), then add WebSocket as an optional upgrade. Keep the JSON wire format identical between both transports so clients can switch seamlessly.

When in doubt, prioritize correct E2E encryption over performance optimizations. Use Go's crypto/subtle for all comparisons. Never log message ciphertexts.
