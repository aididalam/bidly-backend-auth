package service

import (
	"context"
	"errors"
	"testing"

	"auction/auth/internal/model"
	"auction/auth/internal/repository"

	"golang.org/x/crypto/bcrypt"
)

type fakeUsers struct {
	user        model.User
	createErr   error
	findErr     error
	updateErr   error
	updatedHash string
}

func (f *fakeUsers) Create(_ context.Context, name, email, hash string) (model.User, error) {
	if f.createErr != nil {
		return model.User{}, f.createErr
	}
	f.user = model.User{ID: "id", Name: name, Email: email, PasswordHash: hash}
	return f.user, nil
}
func (f *fakeUsers) FindByEmail(context.Context, string) (model.User, error) {
	return f.user, f.findErr
}
func (f *fakeUsers) FindByID(context.Context, string) (model.User, error) {
	return f.user, f.findErr
}
func (f *fakeUsers) UpdatePassword(_ context.Context, _ string, hash string) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	f.updatedHash = hash
	return nil
}

type fakeIssuer struct{}

func (fakeIssuer) Issue(userID, email string) (string, error) { return userID + ":" + email, nil }

func TestRegisterNormalizesAndHashes(t *testing.T) {
	repo := &fakeUsers{}
	svc := New(repo, fakeIssuer{})
	result, err := svc.Register(context.Background(), " Demo User ", " USER@Example.COM ", "secret123")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if result.User.Name != "Demo User" || result.User.Email != "user@example.com" {
		t.Fatalf("unexpected user: %+v", result.User)
	}
	if bcrypt.CompareHashAndPassword([]byte(result.User.PasswordHash), []byte("secret123")) != nil {
		t.Fatal("password was not hashed")
	}
}

func TestRegisterValidationAndConflict(t *testing.T) {
	svc := New(&fakeUsers{}, fakeIssuer{})
	for _, input := range [][3]string{{"", "a@b.com", "secret123"}, {"name", "bad", "secret123"}, {"name", "a@b.com", "short"}} {
		if _, err := svc.Register(context.Background(), input[0], input[1], input[2]); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("expected invalid input for %#v, got %v", input, err)
		}
	}
	svc = New(&fakeUsers{createErr: repository.ErrEmailConflict}, fakeIssuer{})
	if _, err := svc.Register(context.Background(), "name", "a@b.com", "secret123"); !errors.Is(err, ErrEmailConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestLogin(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	repo := &fakeUsers{user: model.User{ID: "id", Email: "user@example.com", PasswordHash: string(hash)}}
	svc := New(repo, fakeIssuer{})
	if _, err := svc.Login(context.Background(), "USER@example.com", "secret123"); err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := svc.Login(context.Background(), "user@example.com", "wrongpass"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
	repo.findErr = repository.ErrNotFound
	if _, err := svc.Login(context.Background(), "nobody@example.com", "secret123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials for missing user, got %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.MinCost)
	repo := &fakeUsers{user: model.User{ID: "id", PasswordHash: string(hash)}}
	svc := New(repo, fakeIssuer{})
	if err := svc.ChangePassword(context.Background(), "id", "secret123", "newsecret123"); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(repo.updatedHash), []byte("newsecret123")) != nil {
		t.Fatal("new password was not hashed")
	}
	if err := svc.ChangePassword(context.Background(), "id", "wrongpass", "newsecret123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
	if err := svc.ChangePassword(context.Background(), "id", "secret123", "short"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid input, got %v", err)
	}
}
