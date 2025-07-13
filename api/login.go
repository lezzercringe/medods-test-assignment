package api

import (
	"assignment/auth"
	"encoding/base64"
	"net"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type LoginHandler struct {
	service *auth.Service
}

func NewLoginHandler(service *auth.Service) *LoginHandler {
	return &LoginHandler{
		service: service,
	}
}

// @Description	Login request payload
type LoginDTO struct {
	//	@Description	Unique identifier for the user
	//	@example		73c954ad-f723-48f4-a76c-d3c29c0cd135
	UserID uuid.UUID `json:"user_id" validate:"required"`
}

// @Description	Login response
type LoginResponse struct {
	//	@Description	JWT access token for authentication
	//	@example		eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
	AccessToken string `json:"access_token"`
	//	@Description	Base64 encoded refresh token
	//	@example		dGVzdC1yZWZyZXNoLXRva2Vu
	RefreshToken string `json:"refresh_token"`
}

// @Summary		Authenticate user
// @Description	Authenticates a user by their UUID
// @Tags			authentication
// @Accept			json
// @Produce		json
// @Param			request	body		LoginDTO		true	"User credentials containing user_id"
// @Success		200		{object}	LoginResponse	"Successfully authenticated - returns access and refresh tokens"
// @Failure		400		{object}	ValidationError	"Validation error - missing or invalid user_id field"
// @Failure		500		{object}	ErrorResponse	"Internal server error - database or service failure"
// @Router			/auth/login [post]
func (h *LoginHandler) Handle(c echo.Context) error {
	var dto LoginDTO
	if err := c.Bind(&dto); err != nil {
		return err
	}

	if dto.UserID == uuid.Nil {
		return &ValidationError{
			Fields: []FieldError{MissingField("user_id")},
		}
	}

	ip, _, err := net.SplitHostPort(c.RealIP())
	if err != nil {
		ip = c.RealIP()
	}

	tokens, err := h.service.AuthenticateUser(c.Request().Context(), auth.AuthenticateUserDTO{
		UserID:    dto.UserID,
		UserAgent: c.Request().Header.Get("User-Agent"),
		IP:        net.ParseIP(ip),
	})

	if err != nil {
		return err
	}

	return c.JSON(200, LoginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: base64.StdEncoding.EncodeToString(tokens.RefreshToken),
	})
}
