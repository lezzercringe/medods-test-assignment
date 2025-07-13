package domain

type HashService interface {
	Hash(b []byte) []byte
	Compare(v []byte, hash []byte) bool
}
