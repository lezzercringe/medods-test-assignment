package domain

import (
	"context"
	"net"
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID               uuid.UUID `postgres:"id"` // unique session identifier, claimed in access token
	RefreshTokenHash []byte    `postgres:"refresh_token_hash"`
	ExpiresAt        time.Time `postgres:"expires_at"`
	Revoked          bool      `postgres:"revoked"`
	UserAgent        string    `postgres:"user_agent"`
	IP               net.IP    `postgres:"ip"`
	UserID           uuid.UUID `postgres:"user_id"`
}

type SessionRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*Session, error)
	Save(ctx context.Context, session Session) (Session, error)
}
