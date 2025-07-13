package jwt

import (
	domain "assignment"
	"assignment/clock"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

var _ domain.TokenService = &TokenService{}

const RefreshTokenLen = 64 // bytes

type TokenService struct {
	clock  clock.Clock
	secret []byte
}

func NewTokenService(clock clock.Clock, secret []byte) *TokenService {
	return &TokenService{
		clock:  clock,
		secret: secret,
	}
}

func (s *TokenService) GenerateTokenPair(claims domain.Claims) domain.IssuedTokens {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.RegisteredClaims{
		Subject:   claims.UserID.String(),
		ExpiresAt: jwt.NewNumericDate(claims.ExpiresAt),
		IssuedAt:  jwt.NewNumericDate(claims.IssuedAt),
		ID:        claims.SessionID.String(),
	})

	accessTokenStr, err := accessToken.SignedString(s.secret)
	if err != nil {
		logrus.WithError(err).Panic("Could not generate an access token")
	}

	refreshToken := make([]byte, RefreshTokenLen)
	if _, err := rand.Reader.Read(refreshToken); err != nil {
		logrus.WithError(err).Panic("Could not generate a refresh token")
	}

	return domain.IssuedTokens{
		AccessToken:  accessTokenStr,
		RefreshToken: refreshToken,
	}
}

func (s *TokenService) ValidateAccessToken(tokenStr string) (domain.Claims, error) {
	var claims jwt.RegisteredClaims
	_, err := jwt.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (interface{}, error) {
		return s.secret, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return domain.Claims{}, domain.ErrExpired
		}

		return domain.Claims{}, fmt.Errorf("could not parse jwt: %w", err)
	}

	return convertRegClaims(claims)
}

func (s *TokenService) ValidateAccessTokenIgnoringExpiration(tokenStr string) (domain.Claims, error) {
	var claims jwt.RegisteredClaims
	_, err := jwt.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (interface{}, error) {
		return s.secret, nil
	})
	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		return domain.Claims{}, fmt.Errorf("could not parse jwt: %w", err)
	}

	return convertRegClaims(claims)
}

func convertRegClaims(claims jwt.RegisteredClaims) (domain.Claims, error) {
	id, err := uuid.Parse(claims.ID)
	if err != nil {
		return domain.Claims{}, fmt.Errorf("could not parse jti claim: %w", err)
	}

	subject, err := uuid.Parse(claims.Subject)
	if err != nil {
		return domain.Claims{}, fmt.Errorf("could not parse sub claim: %w", err)
	}

	expiresAt, err := claims.GetExpirationTime()
	if err != nil {
		return domain.Claims{}, fmt.Errorf("could not parse exp claim: %w", err)
	}

	issuedAt, err := claims.GetIssuedAt()
	if err != nil {
		return domain.Claims{}, fmt.Errorf("could not parse iss claim: %w", err)
	}

	return domain.Claims{
		SessionID: id,
		UserID:    subject,
		ExpiresAt: expiresAt.Time,
		IssuedAt:  issuedAt.Time,
	}, nil
}
