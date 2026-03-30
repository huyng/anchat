package protocol

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// CommandType represents all valid client commands
type CommandType string

const (
	CmdAuth           CommandType = "auth"
	CmdAuthChallenge  CommandType = "auth_challenge"
	CmdBotAuth        CommandType = "bot_auth"
	CmdMsg            CommandType = "msg"
	CmdChannelCreate  CommandType = "channel_create"
	CmdChannelJoin    CommandType = "channel_join"
	CmdChannelSend    CommandType = "channel_send"
	CmdChannelInvite  CommandType = "channel_invite"
	CmdHistorySync    CommandType = "history_sync"
	CmdStatus         CommandType = "status"
	CmdLogout         CommandType = "logout"
)

// SSEEventType represents server-to-client event types
type SSEEventType string

const (
	EventMessage        SSEEventType = "message"
	EventChannelMessage SSEEventType = "channel_message"
	EventUserJoined    SSEEventType = "user_joined"
	EventUserLeft      SSEEventType = "user_left"
	EventError         SSEEventType = "error"
)

// BaseCommand is the common structure for all commands
type BaseCommand struct {
	Cmd CommandType `json:"cmd"`
}

// AuthCommand is the client authentication request (challenge-response)
type AuthCommand struct {
	Cmd          CommandType `json:"cmd"`
	User         string      `json:"user"`
	Signature    string      `json:"signature"`    // Ed25519 signature of challenge
	Challenge    string      `json:"challenge"`    // The challenge being signed
	PubkeyEd25519 string     `json:"pubkey_ed25519"` // Required for new accounts
	PubkeyX25519 string      `json:"pubkey_x25519"`  // Required for new accounts
}

// AuthChallengeRequest is sent by client to request a challenge
type AuthChallengeRequest struct {
	Cmd  CommandType `json:"cmd"`
	User string      `json:"user"`
}

// AuthChallengeResponse is sent by server with the challenge
type AuthChallengeResponse struct {
	Status    string `json:"status"`
	Challenge string `json:"challenge"` // base64url encoded random bytes
}

// BotAuthCommand is for bot authentication
type BotAuthCommand struct {
	Cmd          CommandType `json:"cmd"`
	Token        string     `json:"token"`
	PubkeyEd25519 string    `json:"pubkey_ed25519"`
	PubkeyX25519 string    `json:"pubkey_x25519"`
}

// MsgCommand is for private messages
type MsgCommand struct {
	Cmd        CommandType `json:"cmd"`
	To         string     `json:"to"`
	Ciphertext  string     `json:"ciphertext"` // base64url encoded
	Nonce      string     `json:"nonce"`      // base64url encoded
}

// ChannelCreateCommand creates a new channel
type ChannelCreateCommand struct {
	Cmd         CommandType `json:"cmd"`
	Name        string     `json:"name"`
	InitialKey  string     `json:"initial_key"` // base64url encoded channel key
}

// ChannelJoinCommand joins an existing channel
type ChannelJoinCommand struct {
	Cmd                CommandType `json:"cmd"`
	Name               string     `json:"name"`
	EncryptedChannelKey string     `json:"encrypted_channel_key"` // base64url encoded
}

// ChannelSendCommand sends a message to a channel
type ChannelSendCommand struct {
	Cmd        CommandType `json:"cmd"`
	Channel    string     `json:"channel"`
	Ciphertext string     `json:"ciphertext"` // base64url encoded
	Nonce      string     `json:"nonce"`      // base64url encoded
}

// ChannelInviteCommand invites a user to a channel
type ChannelInviteCommand struct {
	Cmd                    CommandType `json:"cmd"`
	User                   string     `json:"user"`
	Channel                string     `json:"channel"`
	EncryptedKeyForInvitee string     `json:"encrypted_key_for_invitee"` // base64url encoded
}

// HistorySyncCommand requests message history
type HistorySyncCommand struct {
	Cmd     CommandType `json:"cmd"`
	Channel string     `json:"channel"`
	Limit   int        `json:"limit"`
}

// StatusCommand updates user status
type StatusCommand struct {
	Cmd   CommandType `json:"cmd"`
	State string     `json:"state"` // "online", "away", "idle"
}

// LogoutCommand terminates the session
type LogoutCommand struct {
	Cmd CommandType `json:"cmd"`
}

// CommandResponse is the generic response from server
type CommandResponse struct {
	Status    string      `json:"status"` // "ok" or "error"
	CommandID int64       `json:"command_id,omitempty"`
	Error     string      `json:"error,omitempty"`
	Result    interface{} `json:"result,omitempty"`
}

// AuthResponse is returned after successful authentication
type AuthResponse struct {
	Status      string `json:"status"`
	SessionToken string `json:"session_token"`
	UserID      string `json:"user_id"`
}

// MessageEvent is a private message event (SSE)
type MessageEvent struct {
	Type       string `json:"type"`
	From       string `json:"from"`
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	Timestamp  int64  `json:"timestamp"`
}

// ChannelMessageEvent is a channel message event (SSE)
type ChannelMessageEvent struct {
	Type       string `json:"type"`
	Channel    string `json:"channel"`
	From       string `json:"from"`
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	Timestamp  int64  `json:"timestamp"`
}

// UserJoinedEvent is sent when a user joins a channel
type UserJoinedEvent struct {
	Type    string `json:"type"`
	Channel string `json:"channel"`
	User    string `json:"user"`
}

// UserLeftEvent is sent when a user leaves a channel
type UserLeftEvent struct {
	Type    string `json:"type"`
	Channel string `json:"channel"`
	User    string `json:"user"`
}

// ErrorEvent is sent for errors
type ErrorEvent struct {
	Type    string `json:"type"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ParseCommand parses a JSON command string
func ParseCommand(data []byte) (interface{}, error) {
	var base BaseCommand
	if err := json.Unmarshal(data, &base); err != nil {
		return nil, err
	}

	switch base.Cmd {
	case CmdAuth:
		var cmd AuthCommand
		return &cmd, json.Unmarshal(data, &cmd)
	case CmdAuthChallenge:
		var cmd AuthChallengeRequest
		return &cmd, json.Unmarshal(data, &cmd)
	case CmdBotAuth:
		var cmd BotAuthCommand
		return &cmd, json.Unmarshal(data, &cmd)
	case CmdMsg:
		var cmd MsgCommand
		return &cmd, json.Unmarshal(data, &cmd)
	case CmdChannelCreate:
		var cmd ChannelCreateCommand
		return &cmd, json.Unmarshal(data, &cmd)
	case CmdChannelJoin:
		var cmd ChannelJoinCommand
		return &cmd, json.Unmarshal(data, &cmd)
	case CmdChannelSend:
		var cmd ChannelSendCommand
		return &cmd, json.Unmarshal(data, &cmd)
	case CmdChannelInvite:
		var cmd ChannelInviteCommand
		return &cmd, json.Unmarshal(data, &cmd)
	case CmdHistorySync:
		var cmd HistorySyncCommand
		return &cmd, json.Unmarshal(data, &cmd)
	case CmdStatus:
		var cmd StatusCommand
		return &cmd, json.Unmarshal(data, &cmd)
	case CmdLogout:
		return &LogoutCommand{Cmd: CmdLogout}, nil
	default:
		return nil, fmt.Errorf("unknown command: %s", base.Cmd)
	}
}

// MustParseCommand parses a command and panics on error (for tests)
func MustParseCommand(data []byte) interface{} {
	cmd, err := ParseCommand(data)
	if err != nil {
		panic(err)
	}
	return cmd
}

// EncodeBase64URL encodes bytes to base64url without padding
func EncodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// DecodeBase64URL decodes a base64url string
func DecodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
