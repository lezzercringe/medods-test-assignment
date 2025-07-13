package bcrypt

import (
	domain "assignment"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

var _ domain.HashService = &HashService{}

type HashService struct {
}

func NewHashService() *HashService {
	return &HashService{}
}

func (*HashService) Hash(b []byte) []byte {
	hashed, err := bcrypt.GenerateFromPassword(b, bcrypt.DefaultCost)
	if err != nil {
		logrus.WithError(err).Panic("Could not hash password")
	}

	return hashed
}

func (*HashService) Compare(v []byte, hash []byte) bool {
	return bcrypt.CompareHashAndPassword(hash, v) == nil
}
