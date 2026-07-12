package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"auction/auth/internal/token"
)

func TestProtect(t *testing.T) {
	manager := token.NewManager(strings.Repeat("s", 32), time.Hour)
	value, _ := manager.Issue("id", "user@example.com")
	protected := NewAuth(manager).Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok || claims.Subject != "id" {
			t.Fatal("claims missing from context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer "+value)
	response := httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/", nil)
	response = httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", response.Code)
	}
}
