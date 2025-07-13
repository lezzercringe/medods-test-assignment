package auth_test

import (
	domain "assignment"
	"assignment/auth"
	"assignment/mocks"
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

var _ = Describe("AuthService", func() {
	var ctrl *gomock.Controller
	var sessionRepository *mocks.MockSessionRepository
	var revocationList *mocks.MockRevocationList
	var ipNotifier *mocks.MockNonMatchingIPNotifier
	var hashService *mocks.MockHashService
	var clock *mocks.MockClock
	var tokenService *mocks.MockTokenService
	var service *auth.Service

	accessTokenTTL := 10 * time.Second
	refreshTokenTTL := 20 * time.Second

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		sessionRepository = mocks.NewMockSessionRepository(ctrl)
		revocationList = mocks.NewMockRevocationList(ctrl)
		ipNotifier = mocks.NewMockNonMatchingIPNotifier(ctrl)
		hashService = mocks.NewMockHashService(ctrl)
		tokenService = mocks.NewMockTokenService(ctrl)
		clock = mocks.NewMockClock(ctrl)

		service = auth.NewService(auth.Config{
			AccessTokenTTL:  accessTokenTTL,
			RefreshTokenTTL: refreshTokenTTL,
		}, clock, sessionRepository, tokenService, revocationList, ipNotifier, hashService)
	})
	JustAfterEach(func() {
		ctrl.Finish()
	})

	// random data
	timestamp, _ := time.Parse(time.RFC3339, "2025-07-11T14:30:00Z")

	Describe("Authorization", func() {
		accessToken := "abcdef"
		userID := uuid.MustParse("ebefef3b-7f0b-4cd9-a4d5-6bd79df90c7d")
		tokenID := uuid.MustParse("d9c52268-47d3-4336-9fd4-0dab43c4d535")

		Context("when token is valid", func() {
			It("returns claimed user id and no error", func() {
				claims := domain.Claims{
					SessionID: tokenID,
					UserID:    userID,
					ExpiresAt: timestamp,
					IssuedAt:  timestamp,
				}

				tokenService.EXPECT().ValidateAccessToken(gomock.Eq(accessToken)).Return(claims, nil)
				revocationList.EXPECT().Contains(gomock.Any(), tokenID).Return(false, nil)
				actualUserID, err := service.AuthorizeToken(context.Background(), accessToken)

				Expect(err).NotTo(HaveOccurred())
				Expect(actualUserID).To(Equal(userID))
			})
		})

		Context("when token is malformed", func() {
			It("returns uuid.Nil and error matching with auth.ErrMalformedToken", func() {
				err := errors.New("error returned from ValidateAccessToken")

				tokenService.EXPECT().ValidateAccessToken(gomock.Eq(accessToken)).Return(domain.Claims{}, err)
				actualUserID, err := service.AuthorizeToken(context.Background(), accessToken)

				Expect(err).To(And(HaveOccurred(), MatchError(auth.ErrMalformedToken), MatchError(err)))
				Expect(actualUserID).To(Equal(uuid.Nil))
			})
		})

		Context("when token is expired", func() {
			It("returns uuid.Nil and error matching with auth.ErrExpiredToken", func() {
				err := domain.ErrExpired

				tokenService.EXPECT().ValidateAccessToken(gomock.Eq(accessToken)).Return(domain.Claims{}, err)
				actualUserID, err := service.AuthorizeToken(context.Background(), accessToken)

				Expect(err).To(And(HaveOccurred(), MatchError(auth.ErrExpiredToken), MatchError(err)))
				Expect(actualUserID).To(Equal(uuid.Nil))
			})
		})

		Context("when token is in revocation list", func() {
			It("returns uuid.Nil and error matching wtih auth.ErrMalformedToken", func() {
				tokenService.EXPECT().ValidateAccessToken(gomock.Eq(accessToken)).Return(domain.Claims{}, nil)
				revocationList.EXPECT().Contains(context.Background(), uuid.Nil).Return(true, nil)
				actualUserID, err := service.AuthorizeToken(context.Background(), accessToken)

				Expect(err).To(And(HaveOccurred(), MatchError(auth.ErrRevokedToken), MatchError(err)))
				Expect(actualUserID).To(Equal(uuid.Nil))
			})

		})

	})

	Describe("Authentication", func() {
		userID := uuid.MustParse("ebefef3b-7f0b-4cd9-a4d5-6bd79df90c7d")
		ip := net.ParseIP("192.168.1.1")
		userAgent := "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko)"
		expectedTokens := domain.IssuedTokens{
			AccessToken:  "access token",
			RefreshToken: []byte("refresh token"),
		}
		expectedRefreshHash := []byte("hash of refresh token")
		Context("when repository does not fail", func() {
			It("returns tokens and does not error", func() {
				expectedSession := domain.Session{
					ID:               userID,
					RefreshTokenHash: expectedRefreshHash,
					ExpiresAt:        timestamp.Add(refreshTokenTTL),
					Revoked:          false,
					UserAgent:        userAgent,
					IP:               ip,
					UserID:           userID,
				}

				clock.EXPECT().Now().Return(timestamp).AnyTimes()
				tokenService.EXPECT().GenerateTokenPair(MatchClaims(domain.Claims{
					UserID:    userID,
					ExpiresAt: timestamp.Add(accessTokenTTL),
					IssuedAt:  timestamp,
				})).Return(expectedTokens)
				hashService.EXPECT().Hash(expectedTokens.RefreshToken).Return(expectedRefreshHash)
				sessionRepository.EXPECT().Save(gomock.Any(), MatchSession(expectedSession)).Return(expectedSession, nil)

				tokens, err := service.AuthenticateUser(context.Background(), auth.AuthenticateUserDTO{
					UserID:    userID,
					UserAgent: userAgent,
					IP:        ip,
				})

				Expect(err).ToNot(HaveOccurred())
				Expect(tokens).To(Equal(&expectedTokens))
			})
		})

		Context("when repository fails", func() {
			It("returns wrapped error", func() {
				tokens := domain.IssuedTokens{
					AccessToken:  "access token",
					RefreshToken: []byte("refresh token"),
				}
				expectedError := errors.New("expected error")
				timestamp := time.Now()

				clock.EXPECT().Now().Return(timestamp).AnyTimes()
				tokenService.EXPECT().GenerateTokenPair(gomock.Any()).Return(tokens)
				hashService.EXPECT().Hash(tokens.RefreshToken).Return(expectedRefreshHash)
				sessionRepository.EXPECT().Save(gomock.Any(), gomock.Any()).Return(domain.Session{}, expectedError)

				issued, err := service.AuthenticateUser(context.Background(), auth.AuthenticateUserDTO{
					UserID:    userID,
					UserAgent: userAgent,
					IP:        ip,
				})

				Expect(err).To(And(HaveOccurred(), MatchError(expectedError)))
				Expect(issued).To(BeNil())
			})
		})

	})

})

func TestAuth(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Auth Suite")
}

type SessionMatcher struct {
	Expected domain.Session
}

func (m SessionMatcher) Matches(x interface{}) bool {
	actual, ok := x.(domain.Session)
	if !ok {
		return false
	}

	return actual.UserID == m.Expected.UserID &&
		actual.ExpiresAt.Equal(m.Expected.ExpiresAt) &&
		reflect.DeepEqual(actual.RefreshTokenHash, m.Expected.RefreshTokenHash) &&
		actual.Revoked == m.Expected.Revoked &&
		actual.UserAgent == m.Expected.UserAgent &&
		actual.IP.Equal(m.Expected.IP)
}

func (m SessionMatcher) String() string {
	return "matches domain.Session (excluding ID)"
}

func MatchSession(expected domain.Session) gomock.Matcher {
	return SessionMatcher{Expected: expected}
}

type ClaimsMatcher struct {
	Expected domain.Claims
}

func (m ClaimsMatcher) Matches(x interface{}) bool {
	actual, ok := x.(domain.Claims)
	if !ok {
		return false
	}

	return actual.UserID == m.Expected.UserID &&
		actual.ExpiresAt.Equal(m.Expected.ExpiresAt) &&
		actual.IssuedAt.Equal(m.Expected.IssuedAt)
}

func (m ClaimsMatcher) String() string {
	return "matches domain.Claims (excluding ID)"
}

func MatchClaims(expected domain.Claims) gomock.Matcher {
	return ClaimsMatcher{Expected: expected}
}
