-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS session (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    refresh_token_hash BYTEA NOT NULL,
    revoked BOOLEAN NOT NULL,
    user_agent VARCHAR(255) NOT NULL,
    ip INET NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS session;
-- +goose StatementEnd
