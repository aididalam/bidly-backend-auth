package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"auction/auth/internal/middleware"
	"auction/auth/internal/model"
	"auction/auth/internal/service"
	"auction/auth/internal/token"
)

type fakeAuth struct {
	registerResult  service.AuthResult
	registerErr     error
	loginResult     service.AuthResult
	loginErr        error
	user            model.User
	meErr           error
	changeErr       error
	changedUserID   string
	changedCurrent  string
	changedPassword string
}

func (f *fakeAuth) Register(context.Context, string, string, string) (service.AuthResult, error) {
	return f.registerResult, f.registerErr
}
func (f *fakeAuth) Login(context.Context, string, string) (service.AuthResult, error) {
	return f.loginResult, f.loginErr
}
func (f *fakeAuth) Me(context.Context, string) (model.User, error) { return f.user, f.meErr }
func (f *fakeAuth) ChangePassword(_ context.Context, userID, current, next string) error {
	f.changedUserID, f.changedCurrent, f.changedPassword = userID, current, next
	return f.changeErr
}

func TestPublicEndpoints(t *testing.T) {
	manager := token.NewManager(strings.Repeat("s", 32), time.Hour)
	fake := &fakeAuth{registerResult: service.AuthResult{Token: "token", User: model.User{ID: "id"}}}
	h := New(fake, middleware.NewAuth(manager))

	response := request(h, http.MethodPost, "/api/auth/register", `{"name":"User","email":"u@example.com","password":"secret123"}`, "")
	if response.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d: %s", response.Code, response.Body.String())
	}

	fake.registerErr = service.ErrEmailConflict
	response = request(h, http.MethodPost, "/api/auth/register", `{"name":"User","email":"u@example.com","password":"secret123"}`, "")
	if response.Code != http.StatusConflict {
		t.Fatalf("conflict: expected 409, got %d", response.Code)
	}

	fake.loginErr = service.ErrInvalidCredentials
	response = request(h, http.MethodPost, "/api/auth/login", `{"email":"u@example.com","password":"wrongpass"}`, "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("login: expected 401, got %d", response.Code)
	}
}

func TestHealthz(t *testing.T) {
	manager := token.NewManager(strings.Repeat("s", 32), time.Hour)
	h := New(&fakeAuth{}, middleware.NewAuth(manager))

	response := request(h, http.MethodGet, "/healthz", "", "")
	if response.Code != http.StatusOK || response.Body.Len() != 0 {
		t.Fatalf("healthz response: %d %q", response.Code, response.Body.String())
	}
}

func TestProtectedEndpoints(t *testing.T) {
	manager := token.NewManager(strings.Repeat("s", 32), time.Hour)
	value, _ := manager.Issue("id", "u@example.com")
	fake := &fakeAuth{user: model.User{ID: "id", Name: "User", Email: "u@example.com", PasswordHash: "must-not-leak"}}
	h := New(fake, middleware.NewAuth(manager))

	response := request(h, http.MethodGet, "/api/auth/me", "", value)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "must-not-leak") {
		t.Fatalf("me response: %d %s", response.Code, response.Body.String())
	}
	response = request(h, http.MethodPost, "/api/auth/logout", "", value)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("logout response: %d %s", response.Code, response.Body.String())
	}
	response = request(h, http.MethodPost, "/api/auth/change-password", `{"current_password":"secret123","new_password":"newsecret123"}`, value)
	if response.Code != http.StatusNoContent || fake.changedUserID != "id" || fake.changedCurrent != "secret123" || fake.changedPassword != "newsecret123" {
		t.Fatalf("change password response: %d %s", response.Code, response.Body.String())
	}
	fake.changeErr = service.ErrInvalidCredentials
	response = request(h, http.MethodPost, "/api/auth/change-password", `{"current_password":"wrongpass","new_password":"newsecret123"}`, value)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong current password: expected 401, got %d", response.Code)
	}
	response = request(h, http.MethodGet, "/api/auth/me", "", "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated me: expected 401, got %d", response.Code)
	}
}

func TestRejectsMalformedRequest(t *testing.T) {
	manager := token.NewManager(strings.Repeat("s", 32), time.Hour)
	h := New(&fakeAuth{}, middleware.NewAuth(manager))
	for _, body := range []string{`{`, `{"name":"x","unknown":true}`, `{}` + `{}`} {
		response := request(h, http.MethodPost, "/api/auth/register", body, "")
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body %q: expected 400, got %d", body, response.Code)
		}
		var payload map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatalf("error response is not JSON: %v", err)
		}
	}
}

func TestInternalErrorIsSanitized(t *testing.T) {
	manager := token.NewManager(strings.Repeat("s", 32), time.Hour)
	h := New(&fakeAuth{loginErr: errors.New("database password leaked")}, middleware.NewAuth(manager))
	response := request(h, http.MethodPost, "/api/auth/login", `{"email":"u@example.com","password":"secret123"}`, "")
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "database") {
		t.Fatalf("unexpected internal error response: %d %s", response.Code, response.Body.String())
	}
}

func request(h http.Handler, method, path, body, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
