package auth

import (
	domain "assignment"
	"assignment/clock"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type Service struct {
	clock          clock.Clock
	sessionRep     domain.SessionRepository
	revocationList domain.RevocationList
	tokenSvc       domain.TokenService
	hashSvc        domain.HashService
	ipNotifier     domain.NonMatchingIPNotifier

	cfg Config
}

type Config struct {
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

func NewService(
	cfg Config,
	clock clock.Clock,
	sessionRepository domain.SessionRepository,
	tokenService domain.TokenService,
	revocationList domain.RevocationList,
	ipNotifier domain.NonMatchingIPNotifier,
	hashService domain.HashService,
) *Service {
	return &Service{
		clock:          clock,
		sessionRep:     sessionRepository,
		revocationList: revocationList,
		tokenSvc:       tokenService,
		hashSvc:        hashService,
		ipNotifier:     ipNotifier,
		cfg:            cfg,
	}
}

type AuthenticateUserDTO struct {
	UserID    uuid.UUID
	UserAgent string
	IP        net.IP
}

var (
	ErrMalformedToken     = domain.NewBusinessError("invalid or corrupted authentication token", http.StatusUnauthorized)
	ErrRevokedToken       = domain.NewBusinessError("authentication token has been revoked - please log in again", http.StatusUnauthorized)
	ErrExpiredToken       = domain.NewBusinessError("authentication token has expired - please log in again", http.StatusUnauthorized)
	ErrSessionExpired     = domain.NewBusinessError("your session has expired - please log in again", http.StatusUnauthorized)
	ErrSessionRevoked     = domain.NewBusinessError("your session has been revoked - please log in again", http.StatusUnauthorized)
	ErrInvalidCredentials = domain.NewBusinessError("invalid refresh token - please log in again", http.StatusUnauthorized)
	ErrSuspiciousActivity = domain.NewBusinessError("suspicious activity detected - please log in from your original device", http.StatusForbidden)
	ErrTokenCompromised   = domain.NewBusinessError("security issue detected - please log in again", http.StatusUnauthorized)
)

func (s *Service) AuthenticateUser(ctx context.Context, dto AuthenticateUserDTO) (*domain.IssuedTokens, error) {
	sessionID := uuid.New()

	tokens := s.tokenSvc.GenerateTokenPair(domain.Claims{
		SessionID: sessionID,
		UserID:    dto.UserID,
		ExpiresAt: s.clock.Now().Add(s.cfg.AccessTokenTTL),
		IssuedAt:  s.clock.Now(),
	})

	hash := s.hashSvc.Hash(tokens.RefreshToken)
	session := domain.Session{
		ExpiresAt:        s.clock.Now().Add(s.cfg.RefreshTokenTTL),
		UserAgent:        dto.UserAgent,
		IP:               dto.IP,
		UserID:           dto.UserID,
		RefreshTokenHash: hash,
		ID:               sessionID,
	}

	if _, err := s.sessionRep.Save(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create authentication session: %w", err)
	}

	return &tokens, nil
}

func (s *Service) AuthorizeToken(ctx context.Context, accessToken string) (uuid.UUID, error) {
	claims, err := s.tokenSvc.ValidateAccessToken(accessToken)
	if err != nil {
		if errors.Is(err, domain.ErrExpired) {
			return uuid.Nil, ErrExpiredToken
		}

		return uuid.Nil, ErrMalformedToken
	}
	revoked, err := s.revocationList.Contains(ctx, claims.SessionID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("could not check revocation list: %w", err)
	}
	if revoked {
		return uuid.Nil, ErrRevokedToken
	}

	return claims.UserID, nil
}

func (s *Service) RevokeTokenPair(ctx context.Context, accessToken string) error {
	claims, err := s.tokenSvc.ValidateAccessTokenIgnoringExpiration(accessToken)
	if err != nil {
		return ErrMalformedToken
	}

	if err := s.revocationList.Add(ctx, claims.SessionID, claims.ExpiresAt); err != nil {
		if errors.Is(err, domain.ErrDuplicate) {
			return ErrRevokedToken
		}

		return fmt.Errorf("could not add token to revocation list: %w", err)
	}

	session, err := s.sessionRep.GetByID(ctx, claims.SessionID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return ErrSessionExpired
		}
		return fmt.Errorf("could not get session by id: %w", err)
	}

	session.Revoked = true
	if _, err := s.sessionRep.Save(ctx, *session); err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	return nil
}

type RenewAccessTokenDTO struct {
	AccessToken  string
	RefreshToken []byte
	IP           net.IP
	UserAgent    string
}

func (s *Service) RenewAccessToken(ctx context.Context, dto RenewAccessTokenDTO) (*domain.IssuedTokens, error) {
	claims, err := s.tokenSvc.ValidateAccessTokenIgnoringExpiration(dto.AccessToken)
	if err != nil {
		return nil, ErrMalformedToken
	}

	session, err := s.sessionRep.GetByID(ctx, claims.SessionID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrSessionExpired
		}

		return nil, fmt.Errorf("could not get session by id: %w", err)
	}

	// verifying tokens compliance
	if !s.hashSvc.Compare(dto.RefreshToken, session.RefreshTokenHash) {
		// both tokens are compromised, revoking...
		session.Revoked = true
		if _, err := s.sessionRep.Save(ctx, *session); err != nil {
			logrus.WithError(err).Error("Could not save session")
		}

		if err := s.revocationList.Add(ctx, claims.SessionID, claims.ExpiresAt); err != nil {
			logrus.WithError(err).Error("Could not add token to revocation list")
		}

		return nil, ErrTokenCompromised
	}

	if session.Revoked {
		return nil, ErrSessionRevoked
	}

	if session.ExpiresAt.Before(s.clock.Now()) {
		return nil, ErrSessionExpired
	}

	// revoke both tokens anyway
	if err := s.revocationList.Add(ctx, claims.SessionID, claims.ExpiresAt); err != nil {
		return nil, fmt.Errorf("failed to revoke previous tokens: %w", err)
	}

	session.Revoked = true
	if _, err = s.sessionRep.Save(ctx, *session); err != nil {
		return nil, fmt.Errorf("failed to update session status: %w", err)
	}

	// do not generate new pair if prevUserAgent != userAgent
	if dto.UserAgent != session.UserAgent {
		return nil, ErrSuspiciousActivity
	}

	// send notificaiton if ip != prevIP
	if !slices.Equal(dto.IP, session.IP) {
		err := s.ipNotifier.Notify(ctx, domain.IPNotificationDTO{
			PrevIP:    session.IP,
			CurrentIP: dto.IP,
			UserID:    claims.UserID,
		})

		if err != nil {
			logrus.WithError(err).Warn("Could not notify about ip change")
		}
	}

	newSessionID := uuid.New()
	newTokens := s.tokenSvc.GenerateTokenPair(domain.Claims{
		SessionID: newSessionID,
		UserID:    claims.UserID,
		ExpiresAt: s.clock.Now().Add(s.cfg.AccessTokenTTL),
		IssuedAt:  s.clock.Now(),
	})

	newHash := s.hashSvc.Hash(newTokens.RefreshToken)
	newSession := domain.Session{
		RefreshTokenHash: newHash,
		ExpiresAt:        s.clock.Now().Add(s.cfg.RefreshTokenTTL),
		UserAgent:        session.UserAgent,
		IP:               dto.IP,
		UserID:           claims.UserID,
		ID:               newSessionID,
	}

	if _, err := s.sessionRep.Save(ctx, newSession); err != nil {
		return nil, fmt.Errorf("failed to create new authentication session: %w", err)
	}

	return &newTokens, nil
}
