package postgres

import (
	domain "assignment"
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ domain.SessionRepository = &SessionRepository{}

type SessionRepository struct {
	pool *pgxpool.Pool
}

func NewSessionRepository(pool *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{
		pool: pool,
	}
}

func (r *SessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Session, error) {
	query := `
		SELECT id, user_id, refresh_token_hash, expires_at, revoked, user_agent, ip 
		FROM session
		WHERE id = $1
		LIMIT 1;
	`

	var session domain.Session
	if err := r.pool.QueryRow(ctx, query, id).Scan(&session.ID, &session.UserID, &session.RefreshTokenHash, &session.ExpiresAt,
		&session.Revoked, &session.UserAgent, &session.IP); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}

		return nil, err
	}

	return &session, nil
}

func (r *SessionRepository) Save(ctx context.Context, session domain.Session) (domain.Session, error) {
	query := `
		INSERT INTO session (id, refresh_token_hash, user_id, expires_at, revoked, user_agent, ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT(id) DO UPDATE
		SET user_id = excluded.user_id, refresh_token_hash = excluded.refresh_token_hash,
		revoked = excluded.revoked, user_agent = excluded.user_agent, ip = excluded.ip
		RETURNING id, refresh_token_hash, user_id, expires_at, revoked, user_agent, ip ;
	`

	err := r.pool.QueryRow(
		ctx,
		query,
		session.ID,
		session.RefreshTokenHash,
		session.UserID,
		session.ExpiresAt,
		session.Revoked,
		session.UserAgent,
		session.IP,
	).Scan(&session.ID, &session.RefreshTokenHash, &session.UserID, &session.ExpiresAt, &session.Revoked, &session.UserAgent, &session.IP)

	return session, err
}
