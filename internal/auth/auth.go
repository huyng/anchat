package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/huyng/anchat/internal/crypto"
	"github.com/huyng/anchat/internal/db"
	"github.com/huyng/anchat/internal/models"
)

// AuthService handles authentication and session management
type AuthService struct {
	db *db.DB
}

// NewAuthService creates a new authentication service
func NewAuthService(database *db.DB) *AuthService {
	return &AuthService{db: database}
}

// Session represents an active user session
type Session struct {
	UserID    string
	Token     string
	ExpiresAt time.Time
}

// GenerateChallenge creates a random challenge for authentication
func (a *AuthService) GenerateChallenge() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate challenge: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AuthenticateWithSignature validates an Ed25519 signature and authenticates the user.
// If the user doesn't exist, a new account is automatically created (auto-registration).
func (a *AuthService) AuthenticateWithSignature(ctx context.Context, username string, challengeB64, signatureB64 string, pubkeyEd25519, pubkeyX25519 []byte) (*Session, error) {
	// Decode challenge and signature from base64
	challenge, err := base64.RawURLEncoding.DecodeString(challengeB64)
	if err != nil {
		return nil, fmt.Errorf("invalid challenge encoding: %w", err)
	}

	signature, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	usernameHash := models.HashUsername(username)
	user, err := a.db.GetUserByUsername(ctx, usernameHash)

	// Auto-register if user doesn't exist
	if err != nil || user == nil {
		if pubkeyEd25519 == nil || pubkeyX25519 == nil {
			return nil, fmt.Errorf("public keys required for new account")
		}

		user = &models.User{
			UserID:       generateUserID(),
			UsernameHash: usernameHash,
			PubkeyEd25519: pubkeyEd25519,
			PubkeyX25519:  pubkeyX25519,
			CreatedAt:     time.Now(),
		}

		if err := a.db.CreateUser(ctx, user); err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}
	}

	// Verify signature using stored Ed25519 public key
	if !crypto.Verify(challenge, signature, user.PubkeyEd25519) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Generate session token
	sessionToken, err := generateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	// Store session token hash
	sessionTokenHash := models.HashSessionToken(sessionToken)
	if err := a.db.UpdateSessionToken(ctx, user.UserID, sessionTokenHash); err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	session := &Session{
		UserID:    user.UserID,
		Token:     sessionToken,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hour session
	}

	return session, nil
}

// AuthenticateBot authenticates a bot with API token (TODO: implement challenge-response for bots too)
func (a *AuthService) AuthenticateBot(ctx context.Context, token string, pubkeyEd25519, pubkeyX25519 []byte) (*Session, error) {
	// TODO: Implement bot authentication with challenge-response
	return nil, fmt.Errorf("bot authentication not implemented")
}

// ValidateSession validates a session token
func (a *AuthService) ValidateSession(ctx context.Context, sessionToken string) (*models.User, error) {
	sessionTokenHash := models.HashSessionToken(sessionToken)
	user, err := a.db.GetUserBySessionToken(ctx, sessionTokenHash)
	if err != nil {
		return nil, fmt.Errorf("invalid session")
	}
	return user, nil
}

// Logout invalidates a session
func (a *AuthService) Logout(ctx context.Context, userID string) error {
	return a.db.UpdateSessionToken(ctx, userID, nil)
}

// generateUserID generates a unique user ID
func generateUserID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// generateSessionToken generates a session token
func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
