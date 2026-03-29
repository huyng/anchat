# AnChat Implementation Plan

## Current State (2026-03-29)

### Completed ✅
- **Core Server Infrastructure** — HTTP/2 server with graceful shutdown
- **Database Layer** — SQLite schema with CRUD operations
- **Cryptography** — Ed25519, X25519, Argon2id, NaCl box
- **Authentication** — User registration, session-based auth, token validation
- **SSE Streaming** — Basic SSE handler with header setup
- **API Endpoints** — All endpoints defined with request parsing
- **Config System** — TOML-based configuration (added by huyng)
- **Documentation** — PROTOCOL.md, README.md, GETTING_STARTED.md
- **Binary** — Builds successfully (13MB)

### Stubbed (Need Implementation) ⚧️
The following handlers return "Not yet implemented":
- `handleMsg` — Private message E2E routing
- `handleChannelSend` — Channel message routing
- `handleChannelJoin` — Channel join logic
- `handleChannelCreate` — Channel creation logic
- `handleChannelInvite` — Channel invitation logic
- `handleHistorySync` — Message history retrieval
- `handleStatus` — User status updates
- `handleWebSocket` — WebSocket upgrade

### Current Issues
- SSE subscriber system (`s.subscribers`) exists but not integrated with handlers
- No actual message routing between clients
- No channel key management or distribution
- No rate limiting or replay protection

---

## Next Implementation Steps

### Phase 1: Complete Core Message Handlers (Priority: CRITICAL)

These are the minimum requirements for a working chat system.

#### 1.1 Private Messages (`/msg`)
**Goal:** Enable users to send encrypted private messages

**Implementation:**
```go
// internal/server/message_handlers.go

func (s *Server) handleMsg(ctx context.Context, userID string, cmdData map[string]interface{}) protocol.CommandResponse {
    // 1. Parse command
    var cmd protocol.MsgCommand
    if err := mapstructure.Decode(cmdData, &cmd); err != nil {
        return protocol.CommandResponse{
            Status: "error",
            Error:  fmt.Sprintf("Invalid msg command: %v", err),
        }
    }

    // 2. Get recipient's X25519 public key
    recipient, err := s.authService.GetUserByUsername(ctx, cmd.To)
    if err != nil {
        return protocol.CommandResponse{
            Status: "error",
            Error:  "Recipient not found",
        }
    }

    // 3. Store encrypted message in DB
    nonce, err := base64url.StdEncoding.DecodeString(cmd.Nonce)
    if err != nil {
        return protocol.CommandResponse{
            Status: "error",
            Error:  "Invalid nonce encoding",
        }
    }

    ciphertext, err := base64url.StdEncoding.DecodeString(cmd.Ciphertext)
    if err != nil {
        return protocol.CommandResponse{
            Status: "error",
            Error:  "Invalid ciphertext encoding",
        }
    }

    // 4. Store message (server can't decrypt, just forwards)
    msgID, err := s.db.StoreMessage(ctx, &models.Message{
        RecipientID:   &userID, // Private message to recipient
        SenderKeyHash: models.HashKey(recipient.PubkeyX25519),
        EncryptedBlob:  ciphertext,
        Signature:      nil, // TODO: Add signature support
        Timestamp:      time.Now(),
    })
    if err != nil {
        return protocol.CommandResponse{
            Status: "error",
            Error:  fmt.Sprintf("Failed to store message: %v", err),
        }
    }

    // 5. Forward to recipient via SSE
    s.notifyUser(userID, protocol.MessageEvent{
        Type:       "message",
        From:       userID,
        Ciphertext: cmd.Ciphertext,
        Nonce:      cmd.Nonce,
        Timestamp:  time.Now().Unix(),
    })

    return protocol.CommandResponse{
        Status:    "ok",
        CommandID: msgID,
    }
}
```

#### 1.2 Channel Messages (`/channel_send`)
**Goal:** Enable encrypted group chat

**Implementation:**
```go
// internal/server/channel_handlers.go

func (s *Server) handleChannelSend(ctx context.Context, userID string, cmdData map[string]interface{}) protocol.CommandResponse {
    var cmd protocol.ChannelSendCommand
    if err := mapstructure.Decode(cmdData, &cmd); err != nil {
        return errorResponse(err)
    }

    // 1. Verify user is member of channel
    member, err := s.db.GetChannelMember(ctx, cmd.Channel, userID)
    if err != nil {
        return errorResponse(err)
    }

    // 2. Store message
    ciphertext, _ := base64url.StdEncoding.DecodeString(cmd.Ciphertext)
    msgID, err := s.db.StoreMessage(ctx, &models.Message{
        ChannelID:     &cmd.Channel,
        RecipientID:   nil, // Channel message
        SenderKeyHash: models.HashKey([]byte(userID)), // Blind index
        EncryptedBlob:  ciphertext,
        Signature:      nil,
        Timestamp:      time.Now(),
    })
    if err != nil {
        return errorResponse(err)
    }

    // 3. Get all channel members for broadcast
    members, err := s.db.GetChannelMembers(ctx, cmd.Channel)
    if err != nil {
        return errorResponse(err)
    }

    // 4. Broadcast to all members via SSE
    event := protocol.ChannelMessageEvent{
        Channel:    cmd.Channel,
        From:       userID,
        Ciphertext: cmd.Ciphertext,
        Nonce:      cmd.Nonce,
        Timestamp:  time.Now().Unix(),
    }
    for _, member := range members {
        s.notifyUser(member.UserID, event)
    }

    return okResponse(msgID)
}
```

#### 1.3 Channel Join (`/channel_join`)
**Goal:** Allow users to join channels with encrypted channel key

**Implementation:**
```go
func (s *Server) handleChannelJoin(ctx context.Context, userID string, cmdData map[string]interface{}) protocol.CommandResponse {
    var cmd protocol.ChannelJoinCommand
    if err := mapstructure.Decode(cmdData, &cmd); err != nil {
        return errorResponse(err)
    }

    // 1. Verify channel exists
    channel, err := s.db.GetChannelByName(ctx, cmd.Name)
    if err != nil {
        return errorResponse(fmt.Errorf("Channel not found"))
    }

    // 2. Add user to channel
    member := &models.ChannelMember{
        ChannelID: channel.ChannelID,
        UserID:    userID,
        JoinedAt:  time.Now(),
        IsOp:      false,
    }
    if err := s.db.AddChannelMember(ctx, member); err != nil {
        return errorResponse(err)
    }

    // 3. Increment member count
    if err := s.db.IncrementChannelMemberCount(ctx, channel.ChannelID); err != nil {
        return errorResponse(err)
    }

    // 4. Notify existing members
    members, err := s.db.GetChannelMembers(ctx, channel.ChannelID)
    if err != nil {
        return errorResponse(err)
    }

    event := protocol.UserJoinedEvent{
        Channel: channel.ChannelID,
        User:    userID,
    }
    for _, m := range members {
        if m.UserID != userID {
            s.notifyUser(m.UserID, event)
        }
    }

    return okResponse(nil)
}
```

#### 1.4 Channel Create (`/channel_create`)
**Goal:** Allow users to create new channels

**Implementation:**
```go
func (s *Server) handleChannelCreate(ctx context.Context, userID string, cmdData map[string]interface{}) protocol.CommandResponse {
    var cmd protocol.ChannelCreateCommand
    if err := mapstructure.Decode(cmdData, &cmd); err != nil {
        return errorResponse(err)
    }

    // 1. Generate channel ID
    channelID := "#" + cmd.Name + "_" + generateUUID()
    nameHash := models.HashChannelName(cmd.Name)

    // 2. Create channel in DB
    channel := &models.Channel{
        ChannelID:   channelID,
        NameHash:    nameHash,
        MemberCount: 1, // Creator
        CreatedAt:   time.Now(),
    }
    if err := s.db.CreateChannel(ctx, channel); err != nil {
        return errorResponse(err)
    }

    // 3. Add creator as member
    member := &models.ChannelMember{
        ChannelID: channelID,
        UserID:    userID,
        JoinedAt:  time.Now(),
        IsOp:      true, // Creator is op
    }
    if err := s.db.AddChannelMember(ctx, member); err != nil {
        return errorResponse(err)
    }

    return okResponse(map[string]interface{}{
        "channel_id": channelID,
    })
}
```

#### 1.5 History Sync (`/history_sync`)
**Goal:** Allow clients to fetch recent encrypted messages

**Implementation:**
```go
func (s *Server) handleHistorySync(ctx context.Context, userID string, cmdData map[string]interface{}) protocol.CommandResponse {
    var cmd protocol.HistorySyncCommand
    if err := mapstructure.Decode(cmdData, &cmd); err != nil {
        return errorResponse(err)
    }

    var messages []*models.Message
    var err error

    if cmd.Channel != "" {
        // Channel messages
        messages, err = s.db.GetChannelMessages(ctx, cmd.Channel, cmd.Limit)
    } else {
        // Private messages
        messages, err = s.db.GetUserMessages(ctx, userID, cmd.Limit)
    }

    if err != nil {
        return errorResponse(err)
    }

    // Return messages (encrypted, server doesn't have keys)
    channelMessages := make([]protocol.ChannelMessage, 0, len(messages))
    for i, msg := range messages {
        channelMessages[i] = protocol.ChannelMessage{
            Channel:    msg.ChannelID,
            From:       userID, // TODO: Get actual sender
            Ciphertext: base64url.StdEncoding.EncodeToString(msg.EncryptedBlob),
            Nonce:      "", // TODO: Store nonce
            Timestamp:  msg.Timestamp.Unix(),
        }
    }

    return okResponse(map[string]interface{}{
        "messages": channelMessages,
    })
}
```

#### 1.6 Status Updates (`/status`)
**Goal:** Allow users to set online/away/idle status

**Implementation:**
```go
func (s *Server) handleStatus(ctx context.Context, userID string, cmdData map[string]interface{}) protocol.CommandResponse {
    var cmd protocol.StatusCommand
    if err := mapstructure.Decode(cmdData, &cmd); err != nil {
        return errorResponse(err)
    }

    // Validate state
    validStates := map[string]bool{
        "online": true,
        "away":   true,
        "idle":   true,
    }
    if !validStates[cmd.State] {
        return errorResponse(fmt.Errorf("Invalid status state: %s", cmd.State))
    }

    // TODO: Store status in DB (add users.status column)
    // TODO: Broadcast status change to contacts

    return okResponse(nil)
}
```

---

### Phase 2: Subscriber System (Priority: HIGH)

#### 2.1 Implement User-Message Routing
**Goal:** Enable bidirectional message delivery between users

**Implementation:**
```go
// internal/server/subscribers.go

func (s *Server) subscribe(userID string, eventChan chan<- []byte) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.subscribers[userID] = eventChan
}

func (s *Server) unsubscribe(userID string, eventChan chan<- []byte) {
    s.mu.Lock()
    defer s.mu.Unlock()
    if ch, ok := s.subscribers[userID]; ok && ch == eventChan {
        delete(s.subscribers, userID)
    }
}

func (s *Server) notifyUser(userID string, event interface{}) error {
    s.mu.RLock()
    defer s.mu.RUnlock()

    eventCh, ok := s.subscribers[userID]
    if !ok {
        return fmt.Errorf("user %s not subscribed", userID)
    }

    eventData, err := json.Marshal(event)
    if err != nil {
        return err
    }

    select {
    case eventCh <- eventData:
        return nil
    default:
        return fmt.Errorf("user %s channel full", userID)
    }
}

func (s *Server) broadcastToChannel(channelID string, event interface{}) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    members, err := s.db.GetChannelMembers(context.Background(), channelID)
    if err != nil {
        return // Log error
    }

    eventData, _ := json.Marshal(event)
    for _, member := range members {
        eventCh, ok := s.subscribers[member.UserID]
        if ok {
            select {
            case eventCh <- eventData:
            default:
                // Channel full, skip
            }
        }
    }
}
```

---

### Phase 3: Security Features (Priority: HIGH)

#### 3.1 Rate Limiting
**Goal:** Prevent abuse and spam

**Implementation:**
```go
// internal/server/ratelimit.go

import (
    "sync"
    "time"
    "golang.org/x/time/rate"
)

type RateLimiter struct {
    mu      sync.Mutex
    limiters map[string]*rate.Limiter
}

func NewRateLimiter() *RateLimiter {
    return &RateLimiter{
        limiters: make(map[string]*rate.Limiter),
    }
}

func (rl *RateLimiter) Allow(userID string) bool {
    rl.mu.Lock()
    defer rl.mu.Unlock()

    limiter, exists := rl.limiters[userID]
    if !exists {
        // 100 requests per second per user
        limiter = rate.NewLimiter(100, time.Second)
        rl.limiters[userID] = limiter
    }

    return limiter.Allow()
}
```

#### 3.2 Replay Protection
**Goal:** Prevent message replay attacks

**Implementation:**
```go
// Add to message handlers

func (s *Server) validateNonce(ciphertext, nonce string, timestamp int64) error {
    // Check nonce format (24 bytes base64url = 32 chars)
    if len(nonce) != 32 {
        return fmt.Errorf("invalid nonce length")
    }

    // TODO: Store nonces in memory with TTL
    // Reject messages with duplicate nonces from last 5 minutes
    return nil
}
```

---

### Phase 4: WebSocket Support (Priority: MEDIUM)

#### 4.1 WebSocket Upgrade Handler
**Goal:** Enable optional WebSocket transport for low-latency communication

**Implementation:**
```go
// internal/server/websocket.go

import (
    "log"
    "net/http"

    "github.com/gorilla/websocket"
)

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
    // Validate WebSocket upgrade
    upgrader := websocket.Upgrader{
        ReadBufferSize:  1024,
        WriteBufferSize: 1024,
        CheckOrigin: func(r *http.Request) bool {
            return true // TODO: Validate origin in production
        },
        Subprotocols: []string{"anchat.json"},
    }

    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
        return
    }

    // Handle WebSocket connection
    go s.handleWebSocketConnection(conn)
}

func (s *Server) handleWebSocketConnection(conn *websocket.Conn) {
    userID := getUserIDFromConnection(conn)
    s.subscribe(userID, conn)

    defer s.unsubscribe(userID, conn)
    defer conn.Close()

    for {
        _, message, err := conn.ReadMessage()
        if err != nil {
            break
        }

        var cmdData map[string]interface{}
        if err := json.Unmarshal(message, &cmdData); err != nil {
            continue
        }

        // Handle command (same logic as POST endpoint)
        response := s.handleCommandByType(context.Background(), userID, cmdData)
        responseData, _ := json.Marshal(response)

        if err := conn.WriteMessage(responseData); err != nil {
            log.Printf("WebSocket write error: %v", err)
            break
        }
    }
}
```

---

### Phase 5: Bot Authentication (Priority: MEDIUM)

#### 5.1 Bot Auth Endpoint
**Goal:** Enable programmatic bot access with API tokens

**Implementation:**
```go
// internal/server/bot_auth.go

func (s *Server) handleBotAuth(ctx context.Context, w http.ResponseWriter, r *http.Request) protocol.CommandResponse {
    var cmd protocol.BotAuthCommand
    if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
        return errorResponse(err)
    }

    // 1. Decode keys
    pubkeyEd25519, _ := models.DecodePubkey(cmd.PubkeyEd25519)
    pubkeyX25519, _ := models.DecodePubkey(cmd.PubkeyX25519)

    // 2. Validate token
    tokenHash := models.HashToken(cmd.Token)
    bot, err := s.db.GetBotByToken(ctx, tokenHash)
    if err != nil {
        return errorResponse(fmt.Errorf("Invalid bot token"))
    }

    // 3. Update bot's keys if provided
    if !bytes.Equal(bot.PubkeyEd25519, pubkeyEd25519) {
        // TODO: Update bot keys in DB
    }

    // 4. Generate session
    sessionToken, _ := generateSessionToken()

    return okResponse(map[string]interface{}{
        "bot_id": bot.BotID,
    })
}
```

---

### Phase 6: Database Enhancements (Priority: LOW)

#### 6.1 Add Missing Tables/Columns
```sql
-- Add to users table
ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'online';
ALTER TABLE users ADD COLUMN last_seen_at INTEGER;

-- Add to messages table
ALTER TABLE messages ADD COLUMN nonce BLOB;

-- Create bots table
CREATE TABLE bots (
    bot_id TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL,
    pubkey_ed25519 BLOB NOT NULL,
    pubkey_x25519 BLOB NOT NULL,
    scopes TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
```

---

### Phase 7: Testing (Priority: HIGH)

#### 7.1 Unit Tests
```bash
# Test crypto operations
go test ./internal/crypto/...

# Test auth logic
go test ./internal/auth/...

# Test database layer
go test ./internal/db/...
```

#### 7.2 Integration Tests
```bash
# Test two users exchanging messages
go test ./internal/server/...

# Test channel operations
go test ./internal/server/...
```

---

## Implementation Order

1. ✅ Phase 1.1 — `/msg` handler
2. ✅ Phase 1.2 — `/channel_send` handler
3. ✅ Phase 1.3 — `/channel_join` handler
4. ✅ Phase 1.4 — `/channel_create` handler
5. ✅ Phase 1.5 — `/history_sync` handler
6. ✅ Phase 1.6 — `/status` handler
7. ✅ Phase 2 — Subscriber system
8. ✅ Phase 3.1 — Rate limiting
9. ✅ Phase 3.2 — Replay protection
10. ⏸️ Phase 4 — WebSocket (optional)
11. ⏸️ Phase 5 — Bot authentication
12. ⏸️ Phase 6 — DB enhancements
13. ⏸️ Phase 7 — Testing

---

## Dependencies to Add

```bash
go get github.com/mitchellh/mapstructure
go get github.com/gorilla/websocket
go get golang.org/x/time/rate
```

---

## Next Actions

### Immediate (Today)
1. Add `mapstructure` dependency
2. Implement Phase 1.1 (`/msg` handler)
3. Implement Phase 1.2 (`/channel_send` handler)
4. Implement Phase 1.3 (`/channel_join` handler)
5. Implement Phase 1.4 (`/channel_create` handler)
6. Test basic message flow between 2 users
7. Push to fork and update PR

### Short-term (This Week)
1. Complete Phase 1 (all handlers)
2. Implement Phase 2 (subscriber system)
3. Add rate limiting
4. Implement replay protection
5. Write unit tests for completed handlers

### Medium-term (Next Sprint)
1. WebSocket support (optional)
2. Bot authentication
3. Database migrations
4. CLI client implementation
5. Integration test suite

---

## Notes

- **Security Priority:** All message content must be encrypted client-side before reaching server. Server NEVER sees plaintext.
- **Privacy Guarantee:** Do not compromise on E2E encryption for any feature.
- **Testing:** Write tests as you implement each handler. Test with actual encrypted messages.
- **Documentation:** Update GETTING_STARTED.md with new features as they're implemented.

---

*Plan generated: 2026-03-29*
*Author: LLVNClawdBot*
