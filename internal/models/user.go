package models

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"
)

// User represents a user account
type User struct {
	UserID         string     `json:"user_id" db:"user_id"`
	UsernameHash   []byte     `json:"-" db:"username_hash"`       // SHA-256 of normalized username
	PubkeyEd25519  []byte     `json:"-" db:"pubkey_ed25519"`      // for auth (signature verification)
	PubkeyX25519   []byte     `json:"-" db:"pubkey_x25519"`       // for nacl/box encryption
	SessionTokenHash []byte    `json:"-" db:"session_token_hash"`  // SHA-256 of active token
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
}

// Bot represents a bot account
type Bot struct {
	BotID        string    `json:"bot_id" db:"bot_id"`
	TokenHash    []byte    `json:"-" db:"token_hash"`          // SHA-256 of token
	PubkeyEd25519 []byte    `json:"-" db:"pubkey_ed25519"`
	PubkeyX25519 []byte    `json:"-" db:"pubkey_x25519"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	Scopes       string    `json:"scopes" db:"scopes"` // comma-separated: "read,send,admin_channel"
}

// HashUsername normalizes and hashes a username
func HashUsername(username string) []byte {
	// Normalize: lowercase, trim whitespace
	normalized := strings.ToLower(strings.TrimSpace(username))
	hash := sha256.Sum256([]byte(normalized))
	return hash[:]
}

// HashToken hashes an API token
func HashToken(token string) []byte {
	hash := sha256.Sum256([]byte(token))
	return hash[:]
}

// HashSessionToken hashes a session token
func HashSessionToken(token string) []byte {
	hash := sha256.Sum256([]byte(token))
	return hash[:]
}

// EncodePubkey encodes a public key to base64
func EncodePubkey(pubkey []byte) string {
	return base64.StdEncoding.EncodeToString(pubkey)
}

// DecodePubkey decodes a base64 public key
func DecodePubkey(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
