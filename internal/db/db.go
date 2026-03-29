package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"

	"github.com/huyng/anchat/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

// DB wraps the database connection with helper methods
type DB struct {
	*sql.DB
	storageKey []byte
}

// New creates a new database connection
func New(dbPath, storageKey string) (*DB, error) {
	dsn := "file:" + dbPath + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	sqlDB, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)

	db := &DB{
		DB:         sqlDB,
		storageKey: []byte(storageKey),
	}

	if err := db.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return db, nil
}

// initSchema creates all required tables
func (db *DB) initSchema() error {
	schema := `
	-- Users table
	CREATE TABLE IF NOT EXISTS users (
		user_id TEXT PRIMARY KEY,
		username_hash BLOB NOT NULL,
		pubkey_ed25519 BLOB NOT NULL,
		pubkey_x25519 BLOB NOT NULL,
		password_hash BLOB NOT NULL,
		session_token_hash BLOB,
		created_at INTEGER NOT NULL
	);

	-- Bots table
	CREATE TABLE IF NOT EXISTS bots (
		bot_id TEXT PRIMARY KEY,
		token_hash BLOB NOT NULL,
		pubkey_ed25519 BLOB NOT NULL,
		pubkey_x25519 BLOB NOT NULL,
		scopes TEXT NOT NULL,
		created_at INTEGER NOT NULL
	);

	-- Channels table
	CREATE TABLE IF NOT EXISTS channels (
		channel_id TEXT PRIMARY KEY,
		name_hash BLOB NOT NULL,
		member_count INTEGER DEFAULT 0,
		created_at INTEGER NOT NULL
	);

	-- Channel members
	CREATE TABLE IF NOT EXISTS channel_members (
		channel_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		joined_at INTEGER NOT NULL,
		is_op INTEGER DEFAULT 0,
		PRIMARY KEY (channel_id, user_id)
	);

	-- Messages table
	CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		channel_id TEXT,
		recipient_user_id TEXT,
		sender_key_hash BLOB NOT NULL,
		encrypted_blob BLOB NOT NULL,
		signature BLOB NOT NULL,
		timestamp INTEGER NOT NULL
	);

	-- Indexes for performance
	CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id, timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_user_id, timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username_hash);
	CREATE INDEX IF NOT EXISTS idx_bots_token ON bots(token_hash);
	`

	_, err := db.Exec(schema)
	return err
}

// CreateUser creates a new user account
func (db *DB) CreateUser(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (user_id, username_hash, pubkey_ed25519, pubkey_x25519, password_hash, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	_, err := db.ExecContext(ctx, query,
		user.UserID,
		user.UsernameHash,
		user.PubkeyEd25519,
		user.PubkeyX25519,
		user.PasswordHash,
		user.CreatedAt.Unix(),
	)
	return err
}

// GetUserByUsername retrieves a user by username hash
func (db *DB) GetUserByUsername(ctx context.Context, usernameHash []byte) (*models.User, error) {
	query := `
		SELECT user_id, username_hash, pubkey_ed25519, pubkey_x25519, password_hash, session_token_hash, created_at
		FROM users
		WHERE username_hash = ?
	`
	var user models.User
	var sessionTokenHash []byte
	err := db.QueryRowContext(ctx, query, usernameHash).Scan(
		&user.UserID,
		&user.UsernameHash,
		&user.PubkeyEd25519,
		&user.PubkeyX25519,
		&user.PasswordHash,
		&sessionTokenHash,
		&user.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	user.SessionTokenHash = sessionTokenHash
	return &user, nil
}

// GetUserBySessionToken retrieves a user by session token
func (db *DB) GetUserBySessionToken(ctx context.Context, sessionTokenHash []byte) (*models.User, error) {
	query := `
		SELECT user_id, username_hash, pubkey_ed25519, pubkey_x25519, password_hash, session_token_hash, created_at
		FROM users
		WHERE session_token_hash = ?
	`
	var user models.User
	err := db.QueryRowContext(ctx, query, sessionTokenHash).Scan(
		&user.UserID,
		&user.UsernameHash,
		&user.PubkeyEd25519,
		&user.PubkeyX25519,
		&user.PasswordHash,
		&user.SessionTokenHash,
		&user.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateSessionToken updates the session token for a user
func (db *DB) UpdateSessionToken(ctx context.Context, userID string, sessionTokenHash []byte) error {
	query := `UPDATE users SET session_token_hash = ? WHERE user_id = ?`
	_, err := db.ExecContext(ctx, query, sessionTokenHash, userID)
	return err
}

// GetPubkeyX25519 retrieves a user's X25519 public key
func (db *DB) GetPubkeyX25519(ctx context.Context, userID string) ([]byte, error) {
	query := `SELECT pubkey_x25519 FROM users WHERE user_id = ?`
	var pubkey []byte
	err := db.QueryRowContext(ctx, query, userID).Scan(&pubkey)
	return pubkey, err
}

// CreateChannel creates a new channel
func (db *DB) CreateChannel(ctx context.Context, channel *models.Channel) error {
	query := `
		INSERT INTO channels (channel_id, name_hash, member_count, created_at)
		VALUES (?, ?, 0, ?)
	`
	_, err := db.ExecContext(ctx, query,
		channel.ChannelID,
		channel.NameHash,
		channel.CreatedAt.Unix(),
	)
	return err
}

// GetChannelByName retrieves a channel by name hash
func (db *DB) GetChannelByName(ctx context.Context, nameHash []byte) (*models.Channel, error) {
	query := `
		SELECT channel_id, name_hash, member_count, created_at
		FROM channels
		WHERE name_hash = ?
	`
	var channel models.Channel
	err := db.QueryRowContext(ctx, query, nameHash).Scan(
		&channel.ChannelID,
		&channel.NameHash,
		&channel.MemberCount,
		&channel.CreatedAt,
	)
	return &channel, err
}

// AddChannelMember adds a user to a channel
func (db *DB) AddChannelMember(ctx context.Context, member *models.ChannelMember) error {
	query := `
		INSERT OR REPLACE INTO channel_members (channel_id, user_id, joined_at, is_op)
		VALUES (?, ?, ?, ?)
	`
	_, err := db.ExecContext(ctx, query,
		member.ChannelID,
		member.UserID,
		member.JoinedAt.Unix(),
		member.IsOp,
	)
	return err
}

// IncrementChannelMemberCount increments member count
func (db *DB) IncrementChannelMemberCount(ctx context.Context, channelID string) error {
	query := `UPDATE channels SET member_count = member_count + 1 WHERE channel_id = ?`
	_, err := db.ExecContext(ctx, query, channelID)
	return err
}

// GetChannelMember retrieves a specific channel member
func (db *DB) GetChannelMember(ctx context.Context, channelID, userID string) (*models.ChannelMember, error) {
	query := `
		SELECT channel_id, user_id, joined_at, is_op
		FROM channel_members
		WHERE channel_id = ? AND user_id = ?
	`
	var member models.ChannelMember
	err := db.QueryRowContext(ctx, query, channelID, userID).Scan(
		&member.ChannelID,
		&member.UserID,
		&member.JoinedAt,
		&member.IsOp,
	)
	return &member, err
}

// GetChannelMembers retrieves all members of a channel
func (db *DB) GetChannelMembers(ctx context.Context, channelID string) ([]*models.ChannelMember, error) {
	query := `
		SELECT channel_id, user_id, joined_at, is_op
		FROM channel_members
		WHERE channel_id = ?
		ORDER BY joined_at ASC
	`
	rows, err := db.QueryContext(ctx, query, channelID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []*models.ChannelMember
	for rows.Next() {
		var member models.ChannelMember
		err := rows.Scan(&member.ChannelID, &member.UserID, &member.JoinedAt, &member.IsOp)
		if err != nil {
			return nil, err
		}
		members = append(members, &member)
	}
	return members, nil
}

// StoreMessage stores an encrypted message
func (db *DB) StoreMessage(ctx context.Context, msg *models.Message) (int64, error) {
	query := `
		INSERT INTO messages (channel_id, recipient_user_id, sender_key_hash, encrypted_blob, signature, timestamp)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	result, err := db.ExecContext(ctx, query,
		msg.ChannelID,
		msg.RecipientID,
		msg.SenderKeyHash,
		msg.EncryptedBlob,
		msg.Signature,
		msg.Timestamp.Unix(),
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// GetChannelMessages retrieves recent messages from a channel
func (db *DB) GetChannelMessages(ctx context.Context, channelID string, limit int) ([]*models.Message, error) {
	query := `
		SELECT id, channel_id, sender_key_hash, encrypted_blob, signature, timestamp
		FROM messages
		WHERE channel_id = ?
		ORDER BY timestamp DESC
		LIMIT ?
	`
	rows, err := db.QueryContext(ctx, query, channelID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []*models.Message
	for rows.Next() {
		var msg models.Message
		err := rows.Scan(
			&msg.ID,
			&msg.ChannelID,
			&msg.SenderKeyHash,
			&msg.EncryptedBlob,
			&msg.Signature,
			&msg.Timestamp,
		)
		if err != nil {
			return nil, err
		}
		messages = append(messages, &msg)
	}
	return messages, nil
}

// GetUserMessages retrieves recent private messages for a user
func (db *DB) GetUserMessages(ctx context.Context, userID string, limit int) ([]*models.Message, error) {
	query := `
		SELECT id, recipient_user_id, sender_key_hash, encrypted_blob, signature, timestamp
		FROM messages
		WHERE recipient_user_id = ?
		ORDER BY timestamp DESC
		LIMIT ?
	`
	rows, err := db.QueryContext(ctx, query, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []*models.Message
	for rows.Next() {
		var msg models.Message
		err := rows.Scan(
			&msg.ID,
			&msg.RecipientID,
			&msg.SenderKeyHash,
			&msg.EncryptedBlob,
			&msg.Signature,
			&msg.Timestamp,
		)
		if err != nil {
			return nil, err
		}
		messages = append(messages, &msg)
	}
	return messages, nil
}


// Close closes the database connection
func (db *DB) Close() error {
	return db.DB.Close()
}
