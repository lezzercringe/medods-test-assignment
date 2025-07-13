package api

import (
	domain "assignment"
	"assignment/auth"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

type AuthorizationMw struct {
	service *auth.Service
}

func (mw *AuthorizationMw) AuthorizeRequest(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		headerVal := c.Request().Header.Get("Authorization")
		parts := strings.Split(headerVal, " ")
		if len(parts) != 2 {
			return domain.NewBusinessError("no access token provided", http.StatusUnauthorized)
		}

		accessToken := parts[1]
		userID, err := mw.service.AuthorizeToken(c.Request().Context(), accessToken)
		if err != nil {
			return err
		}

		c.Set("userID", userID)
		c.Set("accessToken", accessToken)
		return next(c)
	}
}

func NewAuthorizationMw(service *auth.Service) *AuthorizationMw {
	return &AuthorizationMw{
		service: service,
	}
}

func RejectIfAuthenticated(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if c.Request().Header.Get("Authorization") != "" {
			return domain.NewBusinessError("already authorized", http.StatusForbidden)
		}

		return next(c)
	}
}
