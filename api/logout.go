package api

import (
	"assignment/auth"

	"github.com/labstack/echo/v4"
)

type LogoutHandler struct {
	service *auth.Service
}

func NewLogoutHandler(service *auth.Service) *LogoutHandler {
	return &LogoutHandler{
		service: service,
	}
}

// Handle godoc
//
//	@Summary		Logout user and revoke tokens
//	@Description	Logs out the user and revokes their access and refresh tokens. The session is marked as revoked and tokens are added to the revocation list.
//	@Tags			authentication
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Success		204	"No content - successfully logged out and tokens revoked"
//	@Failure		401	{object}	ErrorResponse	"Unauthorized - invalid or missing access token"
//	@Failure		500	{object}	ErrorResponse	"Internal server error - database or service failure"
//	@Router			/auth/logout [post]
func (h *LogoutHandler) Handle(c echo.Context) error {
	accessToken := (c.Get("accessToken")).(string)
	if err := h.service.RevokeTokenPair(c.Request().Context(), accessToken); err != nil {
		return err
	}

	return c.NoContent(204)
}
