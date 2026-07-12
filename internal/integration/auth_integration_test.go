package integration_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"auction/auth/internal/handler"
	"auction/auth/internal/middleware"
	"auction/auth/internal/repository"
	"auction/auth/internal/service"
	"auction/auth/internal/token"
	"auction/auth/migrations"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
)

func TestAuthFlowMySQL(t *testing.T) {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN is not set")
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("open MySQL: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping MySQL: %v", err)
	}
	if err := migrations.Up(ctx, db); err != nil {
		t.Fatalf("migrate MySQL: %v", err)
	}

	manager := token.NewManager(strings.Repeat("integration-secret-", 3), time.Hour)
	auth := service.New(repository.NewMySQL(db), manager)
	server := httptest.NewServer(handler.New(auth, middleware.NewAuth(manager)))
	defer server.Close()

	email := fmt.Sprintf("auth-%s@example.com", uuid.NewString())
	var registered authResponse
	response := call(t, server.Client(), http.MethodPost, server.URL+"/api/auth/register", map[string]string{
		"name": "Integration User", "email": strings.ToUpper(email), "password": "secret123",
	}, "")
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("register status: %d", response.StatusCode)
	}
	decode(t, response, &registered)
	if registered.Token == "" || registered.User.Email != email || registered.User.PasswordHash != "" {
		t.Fatalf("unexpected register response: %+v", registered)
	}
	defer func() { _, _ = db.Exec("DELETE FROM users WHERE id = ?", registered.User.ID) }()

	response = call(t, server.Client(), http.MethodPost, server.URL+"/api/auth/register", map[string]string{
		"name": "Duplicate", "email": email, "password": "secret123",
	}, "")
	response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate register status: %d", response.StatusCode)
	}

	var loggedIn authResponse
	response = call(t, server.Client(), http.MethodPost, server.URL+"/api/auth/login", map[string]string{
		"email": email, "password": "secret123",
	}, "")
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login status: %d", response.StatusCode)
	}
	decode(t, response, &loggedIn)

	var current userResponse
	response = call(t, server.Client(), http.MethodGet, server.URL+"/api/auth/me", nil, loggedIn.Token)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("me status: %d", response.StatusCode)
	}
	decode(t, response, &current)
	if current.ID != registered.User.ID || current.Email != email || current.PasswordHash != "" {
		t.Fatalf("unexpected me response: %+v", current)
	}

	response = call(t, server.Client(), http.MethodPost, server.URL+"/api/auth/logout", nil, loggedIn.Token)
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status: %d", response.StatusCode)
	}

	response = call(t, server.Client(), http.MethodGet, server.URL+"/api/auth/me", nil, "invalid-token")
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid token status: %d", response.StatusCode)
	}
}

type authResponse struct {
	Token string       `json:"token"`
	User  userResponse `json:"user"`
}

type userResponse struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
}

func call(t *testing.T, client *http.Client, method, url string, body any, bearer string) *http.Response {
	t.Helper()
	var encoded bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&encoded).Encode(body); err != nil {
			t.Fatalf("encode request: %v", err)
		}
	}
	request, err := http.NewRequest(method, url, &encoded)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return response
}

func decode(t *testing.T, response *http.Response, destination any) {
	t.Helper()
	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}
