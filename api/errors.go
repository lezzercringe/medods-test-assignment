package api

import (
	domain "assignment"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

// FieldError represents a validation error for a specific field
// @Description Field-specific validation error
type FieldError struct {
	// @Description Name of the field with error
	// @example user_id
	Field string `json:"field"`
	// @Description Error message for the field
	// @example required, but missing
	Message string `json:"message"`
}

// MissingField creates a standard "required but missing" field error
func MissingField(name string) FieldError {
	return FieldError{
		Field:   name,
		Message: "required, but missing",
	}
}

// ValidationError represents a collection of field validation errors
// @Description Validation error response containing multiple field errors
type ValidationError struct {
	// @Description Array of field validation errors
	Fields []FieldError `json:"fields"`
}

func (e *ValidationError) Error() string {
	return ""
}

// ErrorResponse is the standardized error response structure for all API errors
// @Description Standardized API error response
type ErrorResponse struct {
	// @Description General error message describing the error
	// @example validation error
	Message string `json:"message,omitempty"`
	// @Description Array of field-specific validation errors (only present for validation errors)
	Fields []FieldError `json:"fields,omitempty"`
}

func HandleErrors(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		err := next(c)
		if err == nil {
			return nil
		}

		if _, ok := err.(*echo.HTTPError); ok {
			// echo errors are passed without modification
			return err
		}

		if be, ok := err.(*domain.BusinessError); ok {
			return c.JSON(be.StatusCode, ErrorResponse{Message: be.Message})
		}

		if fe, ok := err.(*ValidationError); ok {
			return c.JSON(http.StatusBadRequest, ErrorResponse{
				Message: "validation error",
				Fields:  fe.Fields,
			})
		}

		logrus.WithError(err).Warn("Unknown error")
		return c.NoContent(500)
	}
}
