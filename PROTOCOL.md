# AnChat Protocol Documentation

## Overview

AnChat uses a simple JSON-based protocol over HTTP/2 with two main transport paths:

- **Client → Server:** HTTP/2 POST with JSON body
- **Server → Client:** Server-Sent Events (SSE) for streaming events

This design ensures:
- Firewall-friendly (port 443, standard HTTPS)
- Native browser support
- Automatic reconnection handling
- Low latency after initial connection

## Transport

### Client → Server: HTTP/2 POST

All commands from client to server are sent via HTTP/2 POST requests:

```
POST /api/v1/command
Authorization: Bearer <session_token>
Content-Type: application/json

{
  "cmd": "msg",
  "to": "bob",
  "ciphertext": "base64url...",
  "nonce": "base64url..."
}
```

**Headers:**
- `Authorization: Bearer <session_token>` — Required for authenticated commands
- `Content-Type: application/json` — All bodies are JSON

**Response:**
```json
{
  "status": "ok",
  "command_id": 12345,
  "result": {}
}
```

Or on error:
```json
{
  "status": "error",
  "error": "Invalid session token"
}
```

### Server → Client: Server-Sent Events (SSE)

Clients maintain a persistent SSE connection to receive events:

```
GET /api/v1/listen
Authorization: Bearer <session_token>

event: message
data: {"type":"private","from":"bob","ciphertext":"base64...","nonce":"base64..."}

event: channel_message
data: {"type":"channel_message","channel":"#rust","from":"carol","ciphertext":"base64...","nonce":"base64..."}
```

**Event Types:**
- `message` — Private message
- `channel_message` — Channel message
- `user_joined` — User joined a channel
- `user_left` — User left a channel
- `error` — Error notification

### Batch Commands

To reduce round trips, multiple commands can be sent in one request:

```
POST /api/v1/command/batch
Authorization: Bearer <session_token>
Content-Type: application/json

{
  "commands": [
    {"cmd": "msg", "to": "bob", "ciphertext": "...", "nonce": "..."},
    {"cmd": "msg", "to": "carol", "ciphertext": "...", "nonce": "..."}
  ]
}
```

**Response:**
```json
{
  "results": [
    {"status": "ok", "command_id": 1},
    {"status": "ok", "command_id": 2}
  ]
}
```

## Authentication Flow (Key-Based, Auto-Registration)

AnChat uses public key authentication with Ed25519 signatures. No passwords are stored — the server only stores public keys. Accounts are automatically created on first successful authentication.

### Step 1: Request Challenge

```
POST /api/v1/auth/challenge
Content-Type: application/json

{
  "cmd": "auth_challenge",
  "user": "alice"
}
```

**Response:**
```json
{
  "status": "ok",
  "challenge": "YSB3b25kZXJmdWwgY2hhbGxlbmdl"
}
```

The challenge is a random 32-byte value, base64url-encoded.

### Step 2: Prove Key Ownership

The client signs the challenge with their Ed25519 private key and sends the signature along with their public keys:

```
POST /api/v1/auth
Content-Type: application/json

{
  "cmd": "auth",
  "user": "alice",
  "pubkey_ed25519": "base64...",
  "pubkey_x25519": "base64...",
  "challenge": "YSB3b25kZXJmdWwgY2hhbGxlbmdl",
  "signature": "base64..."
}
```

**Fields:**
- `pubkey_ed25519` — Required for new accounts (optional for returning users)
- `pubkey_x25519` — Required for new accounts (optional for returning users)
- `challenge` — The challenge from step 1
- `signature` — Ed25519 signature of the challenge bytes

**Response:**
```json
{
  "status": "ok",
  "session_token": "eyJhbGc...",
  "user_id": "alice_abc123"
}
```

If the username doesn't exist, a new account is automatically created (auto-registration). Returning users simply prove they own their private key.

### Step 3: Connect SSE Stream

```
GET /api/v1/listen
Authorization: Bearer eyJhbGc...
```

**Server sends initial event:**
```
event: connected
data: {"user_id":"alice_abc123"}
```

### Step 4: Send Commands

All subsequent commands include the session token in the `Authorization` header.

### Step 5: Logout

```
POST /api/v1/command
Authorization: Bearer eyJhbGc...

{
  "cmd": "logout"
}
```

## Commands (Client → Server)

### `auth_challenge` — Request Authentication Challenge

**Fields:**
- `cmd` (string) — Must be `"auth_challenge"`
- `user` (string) — Username

**Response:**
```json
{
  "status": "ok",
  "challenge": "base64url..."
}
```

### `auth` — Authenticate (with Signature)

**Fields:**
- `cmd` (string) — Must be `"auth"`
- `user` (string) — Username
- `challenge` (string) — The challenge from `auth_challenge` response
- `signature` (string) — Ed25519 signature of the challenge
- `pubkey_ed25519` (string) — Base64-encoded Ed25519 public key (required for new accounts)
- `pubkey_x25519` (string) — Base64-encoded X25519 public key (required for new accounts)

**Response:**
```json
{
  "status": "ok",
  "session_token": "...",
  "user_id": "..."
}
```

**Notes:**
- New accounts are automatically created on successful first authentication
- Returning users omit the public key fields (stored keys are used)

### `bot_auth` — Bot Authentication

**Fields:**
- `cmd` (string) — Must be `"bot_auth"`
- `token` (string) — API token
- `pubkey_ed25519` (string) — Base64-encoded Ed25519 public key
- `pubkey_x25519` (string) — Base64-encoded X25519 public key

**Response:**
```json
{
  "status": "ok",
  "bot_id": "bot_42"
}
```

**Note:** Bot authentication using API tokens is planned but not yet implemented. Bots will also use challenge-response authentication.

### `msg` — Private Message

**Fields:**
- `cmd` (string) — Must be `"msg"`
- `to` (string) — Recipient username or user_id
- `ciphertext` (string) — Base64url-encoded encrypted message (NaCl box)
- `nonce` (string) — Base64url-encoded nonce (24 bytes)

**Response:**
```json
{
  "status": "ok",
  "command_id": 42
}
```

**Server forwards to recipient via SSE:**
```
event: message
data: {
  "type": "private",
  "from": "alice",
  "ciphertext": "base64url...",
  "nonce": "base64url...",
  "timestamp": 1711712000
}
```

**Client-side encryption:**
1. Get recipient's X25519 public key from server
2. Generate random 24-byte nonce
3. Encrypt message with NaCl box: `box.Seal(message, nonce, recipient_pubkey, my_privkey)`
4. Send ciphertext + nonce to server

### `channel_create` — Create Channel

**Fields:**
- `cmd` (string) — Must be `"channel_create"`
- `name` (string) — Channel name (e.g., `#rust`)
- `initial_key` (string) — Base64url-encoded channel symmetric key (ChaCha20-Poly1305)

**Response:**
```json
{
  "status": "ok",
  "result": {
    "channel_id": "#rust_abc123",
    "members": []
  }
}
```

**Channel key management:**
- Client generates random symmetric key (32 bytes)
- Channel key is encrypted to each member's X25519 public key when they join
- Key rotation: Client generates new key, encrypts to all members, broadcasts

### `channel_join` — Join Channel

**Fields:**
- `cmd` (string) — Must be `"channel_join"`
- `name` (string) — Channel name
- `encrypted_channel_key` (string) — Base64url-encoded channel key encrypted with client's X25519 public key

**Response:**
```json
{
  "status": "joined",
  "members": ["alice", "bob", "carol"]
}
```

### `channel_send` — Send to Channel

**Fields:**
- `cmd` (string) — Must be `"channel_send"`
- `channel` (string) — Channel name or ID
- `ciphertext` (string) — Base64url-encoded message encrypted with channel key
- `nonce` (string) — Base64url-encoded nonce

**Response:**
```json
{
  "status": "ok",
  "command_id": 123
}
```

**Server broadcasts to all members via SSE:**
```
event: channel_message
data: {
  "type": "channel_message",
  "channel": "#rust",
  "from": "alice",
  "ciphertext": "base64url...",
  "nonce": "base64url...",
  "timestamp": 1711712000
}
```

### `channel_invite` — Invite User to Channel

**Fields:**
- `cmd` (string) — Must be `"channel_invite"`
- `user` (string) — Username to invite
- `channel` (string) — Channel name
- `encrypted_key_for_invitee` (string) — Base64url-encoded channel key encrypted with invitee's X25519 public key

### `history_sync` — Request Message History

**Fields:**
- `cmd` (string) — Must be `"history_sync"`
- `channel` (string) — Channel name (for channel messages) or empty (for PMs)
- `limit` (int) — Maximum messages to retrieve

**Response:**
```json
{
  "status": "ok",
  "result": {
    "messages": [
      {
        "id": 123,
        "from": "bob",
        "ciphertext": "base64url...",
        "nonce": "base64url...",
        "timestamp": 1711712000
      }
    ]
  }
}
```

### `status` — Update User Status

**Fields:**
- `cmd` (string) — Must be `"status"`
- `state` (string) — One of: `"online"`, `"away"`, `"idle"`

### `logout` — Terminate Session

**Fields:**
- `cmd` (string) — Must be `"logout"`

**Response:**
```json
{
  "status": "ok"
}
```

## Events (Server → Client via SSE)

### `message` — Private Message

```json
{
  "type": "private",
  "from": "bob",
  "ciphertext": "base64url...",
  "nonce": "base64url...",
  "timestamp": 1711712000
}
```

### `channel_message` — Channel Message

```json
{
  "type": "channel_message",
  "channel": "#rust",
  "from": "alice",
  "ciphertext": "base64url...",
  "nonce": "base64url...",
  "timestamp": 1711712000
}
```

### `user_joined` — User Joined Channel

```json
{
  "type": "user_joined",
  "channel": "#rust",
  "user": "carol"
}
```

### `user_left` — User Left Channel

```json
{
  "type": "user_left",
  "channel": "#rust",
  "user": "bob"
}
```

### `error` — Error Notification

```json
{
  "type": "error",
  "code": 401,
  "message": "Session expired"
}
```

**Error Codes:**
- `401` — Unauthorized (invalid session)
- `403` — Forbidden (permission denied)
- `404` — Not found (user/channel not found)
- `429` — Rate limited

## Encryption Model

### End-to-End Encryption (E2E)

AnChat uses **NaCl box** (Curve25519 + ChaCha20-Poly1305) for E2E encryption:

**For Private Messages:**
1. Sender gets recipient's X25519 public key from server
2. Sender generates random 24-byte nonce
3. Sender encrypts: `box.Seal(plaintext, nonce, recipient_pubkey, sender_privkey)`
4. Server stores and forwards ciphertext (cannot decrypt)
5. Recipient decrypts: `box.Open(decrypted, ciphertext, nonce, sender_pubkey, recipient_privkey)`

**For Channels:**
1. Channel has a symmetric key (ChaCha20-Poly1305)
2. Key is encrypted to each member's X25519 public key
3. Messages encrypted with channel key
4. Server sees only ciphertext

**Key Exchange:**
- Out-of-band verification required (like Signal)
- Users compare Ed25519 public key fingerprints
- Blind indexes used for moderation (SHA-256 of pubkeys)

### Authentication

AnChat uses challenge-response authentication with Ed25519 signatures:

1. **Challenge Request**: Client requests a random challenge from server
2. **Sign Challenge**: Client signs the challenge with their Ed25519 private key
3. **Verify Signature**: Server verifies the signature using the stored Ed25519 public key
4. **Session Token**: Server issues a session token valid for 24 hours

**Security Properties:**
- Server never sees private keys
- No passwords to leak or hash
- Challenges prevent replay attacks
- Session tokens expire automatically

### Signatures

Ed25519 keys are used for message signing and authentication:

```
signature = ed25519.Sign(privkey, message)
valid = ed25519.Verify(pubkey, message, signature)
```

## Binary Encoding

All binary data in JSON is **base64url-encoded** (RFC 4648):

- `=` padding is stripped
- `+` and `/` are replaced with `-` and `_`
- URL-safe without needing URL encoding

Example: `aGVsbG8gd29ybGQ==` → `aGVsbG8gd29ybGQ`

## Security Considerations

### Server Cannot Read Messages

- All message content is encrypted **before** reaching the server
- Server stores encrypted blobs only
- At-rest encryption is defense-in-depth, not a substitute for E2E

### Replay Protection

- Each message includes a unique nonce
- Nonces are never reused
- Server rejects messages with duplicate nonces

### Forward Secrecy

- TLS 1.3 with perfect forward secrecy
- Compromised TLS keys cannot decrypt past sessions
- Session tokens expire after 24 hours

### Rate Limiting

- Server enforces rate limits per user
- CAPTCHA for account creation
- Per-channel moderation with blind indexes

## Example Session Flow

```
1. Client → Server: POST /api/v1/auth/challenge
   { "cmd": "auth_challenge", "user": "alice" }

2. Server → Client: 200 OK
   { "status": "ok", "challenge": "abc123..." }

3. Client → Server: POST /api/v1/auth
   { "cmd": "auth", "user": "alice", "challenge": "abc123...", "signature": "...", ... }

4. Server → Client: 200 OK
   { "status": "ok", "session_token": "eyJhbGc...", "user_id": "alice_abc" }

5. Client → Server: GET /api/v1/listen
   Authorization: Bearer eyJhbGc...

6. Server → Client: SSE connected event
   event: connected
   data: {"user_id":"alice_abc"}

7. Client → Server: POST /api/v1/command
   { "cmd": "channel_join", "name": "#rust", ... }

8. Server → Client (via SSE): user joined notification
   event: user_joined
   data: {"channel":"#rust","user":"alice"}

9. Client → Server: POST /api/v1/command
   { "cmd": "channel_send", "channel": "#rust", "ciphertext": "...", "nonce": "..." }

10. Server → Client (via SSE): message to all members
    event: channel_message
    data: {"channel":"#rust","from":"alice","ciphertext":"...","nonce":"..."}
```

## WebSocket (Optional)

Clients can upgrade to WebSocket for bidirectional communication:

```
GET /api/v1/websocket
Upgrade: websocket
Sec-WebSocket-Protocol: anchat.json
```

Same JSON message format as SSE + POST, but over one WebSocket connection.

## Future Extensions

- Federation protocol (server-to-server communication)
- Read receipts (client-only, never sent to server)
- Message edits and deletion
- File transfer
- Voice/video signaling

---

**AnChat Protocol Version:** 1.0
