package server

import (
	"context"
	"fmt"
	"time"

	"github.com/huyng/anchat/internal/db"
	"github.com/huyng/anchat/internal/models"
	"github.com/huyng/anchat/pkg/protocol"
	"github.com/mitchellh/mapstructure"
)

// handleChannelJoin handles joining a channel
func (s *Server) handleChannelJoin(ctx context.Context, userID string, cmdData map[string]interface{}) protocol.CommandResponse {
	var cmd protocol.ChannelJoinCommand
	if err := mapstructure.Decode(cmdData, &cmd); err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Invalid channel_join command: %v", err),
		}
	}

	// Validate required fields
	if cmd.Name == "" {
		return protocol.CommandResponse{
			Status: "error",
			Error:  "Missing 'name' field",
		}
	}

	// Get channel by name hash
	channel, err := s.db.GetChannelByName(ctx, models.HashChannelName(cmd.Name))
	if err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Channel not found: %s", cmd.Name),
		}
	}

	// Optional: Check if user is already member
	_, err = s.db.GetChannelMember(ctx, channel.ChannelID, userID)
	if err == nil {
		// Already a member, just succeed silently
		return protocol.CommandResponse{
			Status: "ok",
			CommandID: 0,
		}
	}

	// Add user to channel
	member := &models.ChannelMember{
		ChannelID: channel.ChannelID,
		UserID:    userID,
		JoinedAt:  time.Now(),
		IsOp:      false,
	}
	if err := s.db.AddChannelMember(ctx, member); err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Failed to join channel: %v", err),
		}
	}

	// Increment member count
	if err := s.db.IncrementChannelMemberCount(ctx, channel.ChannelID); err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Failed to update channel member count: %v", err),
		}
	}

	// Get existing members for notification
	members, err := s.db.GetChannelMembers(ctx, channel.ChannelID)
	if err != nil {
		return protocol.CommandResponse{
			Status: "ok",
			CommandID: 0,
		}
	}

	// Notify existing members
	event := protocol.UserJoinedEvent{
		Channel: channel.ChannelID,
		User:    userID,
	}
	for _, m := range members {
		if m.UserID != userID {
			s.notifyUser(m.UserID, event)
		}
	}

	return protocol.CommandResponse{
		Status: "ok",
		CommandID: 0,
	}
}

// handleChannelCreate handles creating a new channel
func (s *Server) handleChannelCreate(ctx context.Context, userID string, cmdData map[string]interface{}) protocol.CommandResponse {
	var cmd protocol.ChannelCreateCommand
	if err := mapstructure.Decode(cmdData, &cmd); err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Invalid channel_create command: %v", err),
		}
	}

	// Validate required fields
	if cmd.Name == "" {
		return protocol.CommandResponse{
			Status: "error",
			Error:  "Missing 'name' field",
		}
	}
	if cmd.InitialKey == "" {
		return protocol.CommandResponse{
			Status: "error",
			Error:  "Missing 'initial_key' field",
		}
	}

	// Generate channel ID
	channelID := "#" + cmd.Name + "_" + s.generateUUID()

	// Create channel
	channel := &models.Channel{
		ChannelID:   channelID,
		NameHash:    models.HashChannelName(cmd.Name),
		MemberCount: 1,
		CreatedAt:   time.Now(),
	}
	if err := s.db.CreateChannel(ctx, channel); err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Failed to create channel: %v", err),
		}
	}

	// Add creator as member
	member := &models.ChannelMember{
		ChannelID: channelID,
		UserID:    userID,
		JoinedAt:  time.Now(),
		IsOp:      true, // Creator is op
	}
	if err := s.db.AddChannelMember(ctx, member); err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Failed to add creator to channel: %v", err),
		}
	}

	return protocol.CommandResponse{
		Status: "ok",
		CommandID: 0,
	}
}

// handleChannelInvite handles inviting a user to a channel
func (s *Server) handleChannelInvite(ctx context.Context, userID string, cmdData map[string]interface{}) protocol.CommandResponse {
	var cmd protocol.ChannelInviteCommand
	if err := mapstructure.Decode(cmdData, &cmd); err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Invalid channel_invite command: %v", err),
		}
	}

	// Validate required fields
	if cmd.User == "" {
		return protocol.CommandResponse{
			Status: "error",
			Error:  "Missing 'user' field",
		}
	}
	if cmd.Channel == "" {
		return protocol.CommandResponse{
			Status: "error",
			Error:  "Missing 'channel' field",
		}
	}
	if cmd.EncryptedKeyForInvitee == "" {
		return protocol.CommandResponse{
			Status: "error",
			Error:  "Missing 'encrypted_key_for_invitee' field",
		}
	}

	// Verify inviter is member of channel
	_, err := s.db.GetChannelMember(ctx, cmd.Channel, userID)
	if err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Not a member of channel: %s", cmd.Channel),
		}
	}

	// Get invitee's X25519 public key
	invitee, err := s.db.GetUserByUsername(ctx, models.HashUsername(cmd.User))
	if err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Invitee not found: %s", cmd.User),
		}
	}

	// Create invitation message with encrypted channel key
	// The invitee will need to decrypt cmd.EncryptedKeyForInvitee with their X25519 private key
	// to get the channel symmetric key. For now, we just send it as a special event

	invitationEvent := map[string]interface{}{
		"type":    "channel_invite",
		"channel": cmd.Channel,
		"from":    userID,
		"encrypted_channel_key": cmd.EncryptedKeyForInvitee,
	}

	s.notifyUser(invitee.UserID, invitationEvent)

	return protocol.CommandResponse{
		Status: "ok",
		CommandID: 0,
	}
}

// handleHistorySync handles history sync requests
func (s *Server) handleHistorySync(ctx context.Context, userID string, cmdData map[string]interface{}) protocol.CommandResponse {
	var cmd protocol.HistorySyncCommand
	if err := mapstructure.Decode(cmdData, &cmd); err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Invalid history_sync command: %v", err),
		}
	}

	// Validate
	limit := 100 // default limit
	if cmd.Limit > 0 && cmd.Limit <= 1000 {
		limit = cmd.Limit
	}

	var messages []*models.Message
	var err error

	if cmd.Channel != "" {
		// Channel messages
		messages, err = s.db.GetChannelMessages(ctx, cmd.Channel, limit)
	} else {
		// Private messages
		messages, err = s.db.GetUserMessages(ctx, userID, limit)
	}

	if err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Failed to get messages: %v", err),
		}
	}

	// Convert to protocol messages (with base64url encoding)
	channelMessages := make([]protocol.ChannelMessage, 0, len(messages))
	privateMessages := make([]protocol.PrivateMessage, 0, 0)

	for _, msg := range messages {
		if msg.ChannelID != nil {
			// Channel message
			channelMessages = append(channelMessages, protocol.ChannelMessage{
				MessageID:  msg.ID,
				Channel:    *msg.ChannelID,
				From:       userID, // TODO: Get actual sender
				Ciphertext: protocol.EncodeBase64URL(msg.EncryptedBlob),
				Nonce:      "", // TODO: Store nonce
				Timestamp:  msg.Timestamp.Unix(),
			})
		} else if msg.RecipientID != nil && *msg.RecipientID == userID {
			// Private message
			privateMessages = append(privateMessages, protocol.PrivateMessage{
				MessageID:  msg.ID,
				To:         userID,
				From:       "unknown", // TODO: Get actual sender
				Ciphertext: protocol.EncodeBase64URL(msg.EncryptedBlob),
				Nonce:      "", // TODO: Store nonce
				Timestamp:  msg.Timestamp.Unix(),
			})
		}
	}

	return protocol.CommandResponse{
		Status: "ok",
		CommandID: 0,
		Result: map[string]interface{}{
			"messages": append(channelMessages, privateMessages...),
		},
	}
}

// handleStatus handles status updates
func (s *Server) handleStatus(ctx context.Context, userID string, cmdData map[string]interface{}) protocol.CommandResponse {
	var cmd protocol.StatusCommand
	if err := mapstructure.Decode(cmdData, &cmd); err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Invalid status command: %v", err),
		}
	}

	// Validate state
	validStates := map[string]bool{
		"online": true,
		"away":   true,
		"idle":   true,
	}
	if !validStates[cmd.State] {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Invalid status state: %s", cmd.State),
		}
	}

	// TODO: Store status in DB (add status column to users table)
	// For now, we just acknowledge and broadcast to contacts if desired
	return protocol.CommandResponse{
		Status: "ok",
		CommandID: 0,
	}
}

// handleWebSocket handles WebSocket upgrade
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement WebSocket upgrade
	// For now, return not implemented
	protocol.SendSSEError(w, http.StatusNotImplemented, "WebSocket upgrade not yet implemented")
}

// generateUUID generates a random UUID string
func (s *Server) generateUUID() string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(time.Now().UnixNano() >> (i * 8) % 256)
	}
	// Simple base32 encoding
	return string(b[:8])
}

// SendSSEError sends an SSE error event
func SendSSEError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(statusCode)
	event := protocol.ErrorEvent{
		Type:    "error",
		Code:    statusCode,
		Message: message,
	}
	eventData, _ := json.Marshal(event)
	fmt.Fprintf(w, "event: error\ndata: %s\n\n", string(eventData))
}
