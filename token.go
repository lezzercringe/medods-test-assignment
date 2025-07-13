package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type IssuedTokens struct {
	AccessToken  string
	RefreshToken []byte
}

type Claims struct {
	SessionID uuid.UUID
	UserID    uuid.UUID
	ExpiresAt time.Time
	IssuedAt  time.Time
}

type TokenService interface {
	GenerateTokenPair(claims Claims) IssuedTokens

	// ValidateAccessToken checks that token was issued by server and is unexpired
	ValidateAccessToken(tokenStr string) (Claims, error)

	// ValidateAccessTokenIgnoringExpiration only checks that token was issued by server
	// so it can be used in token renewal operation
	ValidateAccessTokenIgnoringExpiration(tokenStr string) (Claims, error)
}

type RevocationList interface {
	Add(ctx context.Context, id uuid.UUID, expiresAt time.Time) error
	Contains(ctx context.Context, id uuid.UUID) (bool, error)
}
