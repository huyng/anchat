package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/huyng/anchat/internal/db"
	"github.com/huyng/anchat/internal/models"
	"github.com/huyng/anchat/pkg/protocol"
	"github.com/mitchellh/mapstructure"
)

// handleMsg handles private messages between users
func (s *Server) handleMsg(ctx context.Context, userID string, cmdData map[string]interface{}) protocol.CommandResponse {
	// Parse command using mapstructure
	var cmd protocol.MsgCommand
	if err := mapstructure.Decode(cmdData, &cmd); err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Invalid msg command: %v", err),
		}
	}

	// Validate required fields
	if cmd.To == "" {
		return protocol.CommandResponse{
			Status: "error",
			Error:  "Missing 'to' field",
		}
	}
	if cmd.Ciphertext == "" {
		return protocol.CommandResponse{
			Status: "error",
			Error:  "Missing 'ciphertext' field",
		}
	}
	if cmd.Nonce == "" {
		return protocol.CommandResponse{
			Status: "error",
			Error:  "Missing 'nonce' field",
		}
	}

	// Get recipient's X25519 public key
	recipient, err := s.db.GetUserByUsername(ctx, models.HashUsername(cmd.To))
	if err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Recipient not found: %s", cmd.To),
		}
	}

	// Decode ciphertext and nonce
	ciphertext, err := protocol.DecodeBase64URL(cmd.Ciphertext)
	if err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Invalid ciphertext encoding: %v", err),
		}
	}

	nonce, err := protocol.DecodeBase64URL(cmd.Nonce)
	if err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Invalid nonce encoding: %v", err),
		}
	}

	// Store encrypted message in DB
	// Server cannot decrypt (E2E), just stores and forwards
	msgID, err := s.db.StoreMessage(ctx, &models.Message{
		RecipientID:   &recipient.UserID,
		SenderKeyHash: db.HashKey(recipient.PubkeyX25519),
		EncryptedBlob:  ciphertext,
		Signature:      nil, // TODO: Add Ed25519 signature support
		Timestamp:      time.Now(),
	})
	if err != nil {
		return protocol.CommandResponse{
			Status: "error",
			Error:  fmt.Sprintf("Failed to store message: %v", err),
		}
	}

	// Forward to recipient via SSE
	// Note: SSE expects base64url encoding for ciphertext/nonce
	s.notifyUser(recipient.UserID, protocol.MessageEvent{
		Type:       "message",
		From:       userID,
		Ciphertext: cmd.Ciphertext, // Keep as base64url for client
		Nonce:      cmd.Nonce,
		Timestamp:  time.Now().Unix(),
	})

	return protocol.CommandResponse{
		Status:    "ok",
		CommandID: msgID,
	}
}
