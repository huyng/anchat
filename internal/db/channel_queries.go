package db

import (
	"context"
	"database/sql"

	"github.com/huyng/anchat/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

// GetChannelMember retrieves a specific channel member
func GetChannelMember(ctx context.Context, db *DB, channelID, userID string) (*models.ChannelMember, error) {
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
func GetChannelMembers(ctx context.Context, db *DB, channelID string) ([]*models.ChannelMember, error) {
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
