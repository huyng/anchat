package server

import (
	"github.com/mitchellh/mapstructure"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/huyng/anchat/internal/auth"
	"github.com/huyng/anchat/internal/db"
	"github.com/huyng/anchat/internal/models"
	"github.com/huyng/anchat/pkg/protocol"
)

// Server is the AnChat HTTP/2 server
type Server struct {
	db          *db.DB
	authService  *auth.AuthService
	httpServer  *http.Server
	time         *time.Time
	tlsCert     string
	tlsKey      string
	tlsEnabled  bool

	// SSE connection management
	mu          sync.RWMutex
	subscribers  map[string]chan<- []byte // userID -> event channel
}

// New creates a new AnChat server
func New(dbPath, storageKey, tlsCert, tlsKey string, tlsEnabled bool) (*Server, error) {
	database, err := db.New(dbPath, storageKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	authService := auth.NewAuthService(database)

	server := &Server{
		db:         database,
		authService: authService,
		tlsCert:    tlsCert,
		tlsKey:     tlsKey,
		tlsEnabled: tlsEnabled,
		subscribers: make(map[string]chan<- []byte),
	}

	return server, nil
}

// Start starts the HTTP/2 server
func (s *Server) Start(addr string) error {
	mux := http.NewServeMux()

	// SSE endpoint
	mux.HandleFunc("/api/v1/listen", s.handleListen)

	// Command endpoints
	mux.HandleFunc("/api/v1/auth", s.handleAuth)
	mux.HandleFunc("/api/v1/command", s.handleCommand)
	mux.HandleFunc("/api/v1/command/batch", s.handleBatchCommand)

	// Optional WebSocket upgrade
	mux.HandleFunc("/api/v1/websocket", s.handleWebSocket)

	// Health check
	mux.HandleFunc("/health", s.handleHealth)

	// Configure HTTP/2
	s.httpServer = &http.Server{
		Addr:    addr,
		Handler:  mux,
		ErrorLog: log.New(log.Writer(), "[HTTP] ", log.LstdFlags),
	}

	log.Printf("Starting AnChat server on %s", addr)

	if s.tlsEnabled {
		return s.httpServer.ListenAndServeTLS(s.tlsCert, s.tlsKey)
	}
	return s.httpServer.ListenAndServe()
}

// Stop gracefully shuts down the server
func (s *Server) Stop(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// handleListen handles SSE connections for receiving events
func (s *Server) handleListen(w http.ResponseWriter, r *http.Request) {
	// Validate session token
	sessionToken := r.Header.Get("Authorization")
	if sessionToken == "" {
		http.Error(w, "Unauthorized: missing session token", http.StatusUnauthorized)
		return
	}

	// Remove "Bearer " prefix
	if len(sessionToken) > 7 && sessionToken[:7] == "Bearer " {
		sessionToken = sessionToken[7:]
	}

	// Validate session
	ctx := r.Context()
	user, err := s.authService.ValidateSession(ctx, sessionToken)
	if err != nil {
		http.Error(w, "Unauthorized: invalid session", http.StatusUnauthorized)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Check if flushing is supported
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	// Create event channel for this user
	eventChan := make(chan []byte, 100)
	s.subscribe(user.UserID, eventChan)
	defer s.unsubscribe(user.UserID, eventChan)

	log.Printf("SSE connection established for user: %s", user.UserID)

	// Send connected event
	s.sendSSEEvent(w, "connected", map[string]string{
		"user_id": user.UserID,
	})
	flusher.Flush()

	// Stream events
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-eventChan:
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(event))
			flusher.Flush()
		}
	}
}

// handleAuth handles user authentication
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var cmd protocol.AuthCommand
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Decode public keys
	pubkeyEd25519, err := models.DecodePubkey(cmd.PubkeyEd25519)
	if err != nil {
		http.Error(w, "Invalid Ed25519 public key", http.StatusBadRequest)
		return
	}

	pubkeyX25519, err := models.DecodePubkey(cmd.PubkeyX25519)
	if err != nil {
		http.Error(w, "Invalid X25519 public key", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	session, err := s.authService.AuthenticateUser(ctx, cmd.User, cmd.Password, pubkeyEd25519, pubkeyX25519)
	if err != nil {
		log.Printf("Auth failed for user %s: %v", cmd.User, err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	response := protocol.AuthResponse{
		Status:      "ok",
		SessionToken: session.Token,
		UserID:      session.UserID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	log.Printf("User authenticated: %s", cmd.User)
}

// handleCommand handles client commands
func (s *Server) handleCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate session token
	sessionToken := r.Header.Get("Authorization")
	if sessionToken == "" {
		http.Error(w, "Unauthorized: missing session token", http.StatusUnauthorized)
		return
	}

	if len(sessionToken) > 7 && sessionToken[:7] == "Bearer " {
		sessionToken = sessionToken[7:]
	}

	ctx := r.Context()
	user, err := s.authService.ValidateSession(ctx, sessionToken)
	if err != nil {
		http.Error(w, "Unauthorized: invalid session", http.StatusUnauthorized)
		return
	}

	// Parse command
	var cmdData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&cmdData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Handle command based on type
	response := s.handleCommandByType(ctx, user.UserID, cmdData)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleBatchCommand handles multiple commands in one request
func (s *Server) handleBatchCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate session token
	sessionToken := r.Header.Get("Authorization")
	if sessionToken == "" {
		http.Error(w, "Unauthorized: missing session token", http.StatusUnauthorized)
		return
	}

	if len(sessionToken) > 7 && sessionToken[:7] == "Bearer " {
		sessionToken = sessionToken[7:]
	}

	ctx := r.Context()
	user, err := s.authService.ValidateSession(ctx, sessionToken)
	if err != nil {
		http.Error(w, "Unauthorized: invalid session", http.StatusUnauthorized)
		return
	}

	var batchReq map[string][]interface{}
	if err := json.NewDecoder(r.Body).Decode(&batchReq); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Process each command
	commands, ok := batchReq["commands"]
	if !ok {
		http.Error(w, "Missing 'commands' field", http.StatusBadRequest)
		return
	}

	responses := make([]protocol.CommandResponse, 0, len(commands))
	for _, cmd := range commands {
		cmdData, ok := cmd.(map[string]interface{})
		if !ok {
			responses = append(responses, protocol.CommandResponse{
				Status: "error",
				Error:  "Invalid command format",
			})
			continue
		}
		resp := s.handleCommandByType(ctx, user.UserID, cmdData)
		responses = append(responses, resp)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"results": responses,
	})
}

// handleWebSocket handles WebSocket upgrade (optional)
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement WebSocket upgrade
	http.Error(w, "WebSocket not yet implemented", http.StatusNotImplemented)
}

// handleHealth returns server health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// handleCommandByType routes commands to their handlers


// handleChannelSend handles channel messages
func (s *Server) handleChannelSend(ctx context.Context, userID string, cmdData map[string]interface{}) protocol.CommandResponse {
	var cmd protocol.ChannelSendCommand
	if err := mapstructure.Decode(cmdData, &cmd); err != nil {
		return protocol.CommandResponse{Status: "error", Error: fmt.Sprintf("Invalid channel_send command: %v", err)}
	}

	// Validate required fields
	if cmd.Channel == "" {
		return protocol.CommandResponse{Status: "error", Error: "Missing 'channel' field"}
	}
	if cmd.Ciphertext == "" {
		return protocol.CommandResponse{Status: "error", Error: "Missing 'ciphertext' field"}
	}
	if cmd.Nonce == "" {
		return protocol.CommandResponse{Status: "error", Error: "Missing 'nonce' field"}
	}

	// Verify user is member of channel
	_, err := s.db.GetChannelMember(ctx, cmd.Channel, userID)
	if err != nil {
		return protocol.CommandResponse{Status: "error", Error: fmt.Sprintf("Not a member of channel: %s", cmd.Channel)}
	}

	// Store channel message
	ciphertext, err := protocol.DecodeBase64URL(cmd.Ciphertext)
	if err != nil {
		return protocol.CommandResponse{Status: "error", Error: fmt.Sprintf("Invalid ciphertext encoding: %v", err)}
	}

	msgID, err := s.db.StoreMessage(ctx, &models.Message{
		ChannelID:     &cmd.Channel,
		RecipientID:   nil, // Channel message (not private)
		SenderKeyHash: db.HashKey([]byte(userID)),
		EncryptedBlob:  ciphertext,
		Signature:      nil,
		Timestamp:      time.Now(),
	})
	if err != nil {
		return protocol.CommandResponse{Status: "error", Error: fmt.Sprintf("Failed to store message: %v", err)}
	}

	// Broadcast to all members via SSE
	members, err := s.db.GetChannelMembers(ctx, cmd.Channel)
	if err != nil {
		return protocol.CommandResponse{Status: "error", Error: fmt.Sprintf("Failed to get channel members: %v", err)}
	}

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

	return protocol.CommandResponse{Status: "ok", CommandID: msgID}
}
// handleChannelInvite handles inviting a user to a channel
func (s *Server) handleChannelInvite(ctx context.Context, userID string, cmdData map[string]interface{}) protocol.CommandResponse {
	// TODO: Implement channel invite
	return protocol.CommandResponse{
		Status: "error",
		Error:  "Not yet implemented",
	}
}

// handleHistorySync handles history sync requests
func (s *Server) handleHistorySync(ctx context.Context, userID string, cmdData map[string]interface{}) protocol.CommandResponse {
	// TODO: Implement history sync
	return protocol.CommandResponse{
		Status: "error",
		Error:  "Not yet implemented",
	}
}

// handleStatus handles status updates
func (s *Server) handleStatus(ctx context.Context, userID string, cmdData map[string]interface{}) protocol.CommandResponse {
	// TODO: Implement status
	return protocol.CommandResponse{
		Status: "error",
		Error:  "Not yet implemented",
	}
}

func (s *Server) handleCommandByType(ctx context.Context, userID string, cmdData map[string]interface{}) protocol.CommandResponse {
	cmdType, ok := cmdData["cmd"].(string)
	if !ok {
		return protocol.CommandResponse{
			Status: "error",
			Error:  "Missing 'cmd' field",
		}
	}

	switch protocol.CommandType(cmdType) {
	case protocol.CmdMsg:
		// Import from message_handlers
		return s.handleMsg(ctx, userID, cmdData)
	case protocol.CmdChannelSend:
		return s.handleChannelSend(ctx, userID, cmdData)
	case protocol.CmdChannelJoin:
		return s.handleChannelJoin(ctx, userID, cmdData)
	case protocol.CmdChannelCreate:
		return s.handleChannelCreate(ctx, userID, cmdData)
	case protocol.CmdChannelInvite:
		return s.handleChannelInvite(ctx, userID, cmdData)
	case protocol.CmdHistorySync:
		return s.handleHistorySync(ctx, userID, cmdData)
	case protocol.CmdStatus:
		return s.handleStatus(ctx, userID, cmdData)
	case protocol.CmdLogout:
		return s.handleLogout(ctx, userID)
	default:
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Unknown command: %s", cmdType),
		}
	}
}


func (s *Server) handleLogout(ctx context.Context, userID string) protocol.CommandResponse {
	if err := s.authService.Logout(ctx, userID); err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Logout failed: %v", err),
		}
	}
	return protocol.CommandResponse{Status: "ok"}
}

// subscribe adds a user's event channel
func (s *Server) subscribe(userID string, eventChan chan<- []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subscribers[userID] = eventChan
}

// unsubscribe removes a user's event channel
func (s *Server) unsubscribe(userID string, eventChan chan<- []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, ok := s.subscribers[userID]; ok && ch == eventChan {
		delete(s.subscribers, userID)
	}
}

// sendSSEEvent sends an SSE event to a connection
func (s *Server) sendSSEEvent(w http.ResponseWriter, event string, data interface{}) {
	eventData, _ := json.Marshal(data)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, string(eventData))
}

// notifyUser sends an SSE event to a specific user
func (s *Server) notifyUser(userID string, event interface{}) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	eventCh, ok := s.subscribers[userID]
	if !ok {
		return
	}

	eventData, err := json.Marshal(event)
	if err != nil {
		return
	}

	select {
	case eventCh <- eventData:
	default:
		// Channel full, skip
	}
}
