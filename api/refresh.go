package api

import (
	"assignment/auth"
	"encoding/base64"
	"net"
	"net/http"

	"github.com/labstack/echo/v4"
)

type RefreshHandler struct {
	service *auth.Service
}

func NewRefreshHandler(service *auth.Service) *RefreshHandler {
	return &RefreshHandler{
		service: service,
	}
}

// RefreshDTO represents the refresh token pair request payload
//
//	@Description	Refresh token request payload
type RefreshDTO struct {
	//	@Description	Current JWT access token
	//	@example		eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
	AccessToken string `json:"access_token" validate:"required"`
	//	@Description	Base64 encoded refresh token
	//	@example		dGVzdC1yZWZyZXNoLXRva2Vu
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// RefreshResponse represents the refresh token response
//
//	@Description	Refresh token response
type RefreshResponse struct {
	//	@Description	New JWT access token
	//	@example		eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
	AccessToken string `json:"access_token"`
	//	@Description	New base64 encoded refresh token
	//	@example		dGVzdC1yZWZyZXNoLXRva2Vu
	RefreshToken string `json:"refresh_token"`
}

// @Summary		Refresh token pair
// @Description	Refreshes the access token using a valid, co-issued token pair
// @Tags			authentication
// @Accept			json
// @Produce		json
// @Param			request	body		RefreshDTO		true	"Refresh token request containing access and refresh tokens"
// @Success		200		{object}	RefreshResponse	"Successfully refreshed token pair - returns new access and refresh tokens"
// @Failure		400		{object}	ValidationError	"Validation error - missing tokens, invalid base64 encoding, or malformed request"
// @Failure		401		{object}	ErrorResponse	"Authentication error - expired tokens, revoked session, or invalid credentials"
// @Failure		403		{object}	ErrorResponse	"Forbidden - suspicious activity detected (different user agent)"
// @Failure		500		{object}	ErrorResponse	"Internal server error - database or service failure"
// @Router			/auth/refresh [post]
func (h *RefreshHandler) Handle(c echo.Context) error {
	var dto RefreshDTO
	if err := c.Bind(&dto); err != nil {
		return err
	}

	var fieldErrors []FieldError
	if len(dto.AccessToken) == 0 {
		fieldErrors = append(fieldErrors, MissingField("access_token"))
	}

	if len(dto.RefreshToken) == 0 {
		fieldErrors = append(fieldErrors, MissingField("refresh_token"))
	}

	if len(fieldErrors) != 0 {
		return &ValidationError{Fields: fieldErrors}
	}

	ip, _, err := net.SplitHostPort(c.Request().RemoteAddr)
	if err != nil {
		ip = c.Request().RemoteAddr
	}

	refreshToken, err := base64.StdEncoding.DecodeString(dto.RefreshToken)
	if err != nil {
		return &ValidationError{Fields: []FieldError{{
			Field:   "refresh_token",
			Message: "invalid base64",
		}}}
	}

	newTokens, err := h.service.RenewAccessToken(c.Request().Context(), auth.RenewAccessTokenDTO{
		AccessToken:  dto.AccessToken,
		RefreshToken: refreshToken,
		IP:           net.ParseIP(ip),
		UserAgent:    c.Request().Header.Get("User-Agent"),
	})
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, RefreshResponse{
		AccessToken:  newTokens.AccessToken,
		RefreshToken: base64.StdEncoding.EncodeToString(newTokens.RefreshToken),
	})
}
