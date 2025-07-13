-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS revoked_token (
    token_id UUID PRIMARY KEY REFERENCES session(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS revoked_token;
-- +goose StatementEnd
