package postgres

import (
	domain "assignment"
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ domain.RevocationList = &RevocationList{}

const uniqueViolationErrCode = "23505"

type RevocationList struct {
	pool *pgxpool.Pool
}

func NewRevocationList(pool *pgxpool.Pool) *RevocationList {
	return &RevocationList{
		pool: pool,
	}
}

func (l *RevocationList) Add(ctx context.Context, id uuid.UUID, expiresAt time.Time) error {
	query := `
		INSERT INTO revoked_token (token_id, expires_at) VALUES ($1, $2);
	`

	if _, err := l.pool.Exec(ctx, query, id, expiresAt); err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == uniqueViolationErrCode {
			return domain.ErrDuplicate
		}

		return err
	}

	return nil
}

func (l *RevocationList) Contains(ctx context.Context, id uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM revoked_token WHERE token_id = $1
		);
	`

	var exists bool
	err := l.pool.QueryRow(ctx, query, id).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}
