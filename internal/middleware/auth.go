package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"auction/auth/internal/token"
)

type contextKey int

const claimsKey contextKey = iota

type Auth struct {
	verifier token.Verifier
}

func NewAuth(verifier token.Verifier) *Auth {
	return &Auth{verifier: verifier}
}

func (a *Auth) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		parts := strings.Fields(header)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			unauthorized(w)
			return
		}
		claims, err := a.verifier.Verify(parts[1])
		if err != nil {
			unauthorized(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey, claims)))
	})
}

func ClaimsFromContext(ctx context.Context) (token.Claims, bool) {
	claims, ok := ctx.Value(claimsKey).(token.Claims)
	return claims, ok
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{
		"code": "unauthorized", "message": "authentication is required",
	}})
}
