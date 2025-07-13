package domain

import "errors"

var (
	ErrNotFound  = errors.New("entity cannot not be found")
	ErrMalformed = errors.New("input malformed")
	ErrDuplicate = errors.New("duplicate entity")
	ErrExpired   = errors.New("stale")
)

type BusinessError struct {
	Message    string
	StatusCode int
}

func (e *BusinessError) Error() string {
	return e.Message
}

func NewBusinessError(message string, status int) *BusinessError {
	return &BusinessError{Message: message, StatusCode: status}
}
