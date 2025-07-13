package api

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type UserHandler struct{}

func NewUserHandler() *UserHandler { return &UserHandler{} }

// @Description	User information response
type UserResponse struct {
	//	@Description	Unique identifier of the authenticated user
	//	@example		73c954ad-f723-48f4-a76c-d3c29c0cd135
	UserID uuid.UUID `json:"user_id"`
}

// @Summary		Get current user information
// @Description	Returns information about the currently authenticated user based on the access token
// @Tags			user
// @Accept			json
// @Produce		json
// @Security		BearerAuth
// @Success		200	{object}	UserResponse	"User information retrieved successfully - returns user_id"
// @Failure		401	{object}	ErrorResponse	"Unauthorized - invalid, expired, or revoked access token"
// @Router			/user [get]
func (h *UserHandler) Handle(c echo.Context) error {
	userID, _ := (c.Get("userID")).(uuid.UUID)
	return c.JSON(http.StatusOK, UserResponse{UserID: userID})
}
