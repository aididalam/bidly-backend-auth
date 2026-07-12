package token

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestIssueAndVerify(t *testing.T) {
	manager := NewManager(strings.Repeat("s", 32), time.Hour)
	value, err := manager.Issue("user-id", "user@example.com")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := manager.Verify(value)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "user-id" || claims.Email != "user@example.com" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestVerifyRejectsExpiredAndWrongAlgorithm(t *testing.T) {
	manager := NewManager(strings.Repeat("s", 32), time.Hour)
	manager.now = func() time.Time { return time.Now().Add(-2 * time.Hour) }
	expired, _ := manager.Issue("user-id", "user@example.com")
	if _, err := manager.Verify(expired); err == nil {
		t.Fatal("expected expired token to fail")
	}

	claims := Claims{Email: "user@example.com", RegisteredClaims: jwt.RegisteredClaims{
		Subject: "user-id", Issuer: "auth-service", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}}
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := manager.Verify(none); err == nil {
		t.Fatal("expected none algorithm to fail")
	}
}
