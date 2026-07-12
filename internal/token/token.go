package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalid = errors.New("invalid token")

type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

type Issuer interface {
	Issue(string, string) (string, error)
}

type Verifier interface {
	Verify(string) (Claims, error)
}

type Manager struct {
	secret []byte
	expiry time.Duration
	now    func() time.Time
}

func NewManager(secret string, expiry time.Duration) *Manager {
	return &Manager{secret: []byte(secret), expiry: expiry, now: time.Now}
}

func (m *Manager) Issue(userID, email string) (string, error) {
	now := m.now().UTC()
	claims := Claims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    "auth-service",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.expiry)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
}

func (m *Manager) Verify(value string) (Claims, error) {
	claims := Claims{}
	parsed, err := jwt.ParseWithClaims(value, &claims, func(parsed *jwt.Token) (any, error) {
		if parsed.Method != jwt.SigningMethodHS256 {
			return nil, ErrInvalid
		}
		return m.secret, nil
	}, jwt.WithIssuer("auth-service"), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || !parsed.Valid || claims.Subject == "" || claims.Email == "" {
		return Claims{}, ErrInvalid
	}
	return claims, nil
}
