package service

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"unicode/utf8"

	"auction/auth/internal/model"
	"auction/auth/internal/repository"
	"auction/auth/internal/token"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidInput       = errors.New("invalid input")
	ErrEmailConflict      = errors.New("email already exists")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserNotFound       = errors.New("user not found")
)

type AuthResult struct {
	Token string     `json:"token"`
	User  model.User `json:"user"`
}

type AuthService interface {
	Register(context.Context, string, string, string) (AuthResult, error)
	Login(context.Context, string, string) (AuthResult, error)
	Me(context.Context, string) (model.User, error)
}

type Service struct {
	users             repository.UserRepository
	tokens            token.Issuer
	dummyPasswordHash []byte
}

func New(users repository.UserRepository, tokens token.Issuer) *Service {
	dummyPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("invalid-password-placeholder"), bcrypt.DefaultCost)
	return &Service{users: users, tokens: tokens, dummyPasswordHash: dummyPasswordHash}
}

func (s *Service) Register(ctx context.Context, name, email, password string) (AuthResult, error) {
	name = strings.TrimSpace(name)
	email, ok := normalizeEmail(email)
	if name == "" || utf8.RuneCountInString(name) > 120 || !ok || len(password) < 8 || len(password) > 72 {
		return AuthResult{}, ErrInvalidInput
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return AuthResult{}, err
	}
	user, err := s.users.Create(ctx, name, email, string(hash))
	if errors.Is(err, repository.ErrEmailConflict) {
		return AuthResult{}, ErrEmailConflict
	}
	if err != nil {
		return AuthResult{}, err
	}
	return s.result(user)
}

func (s *Service) Login(ctx context.Context, email, password string) (AuthResult, error) {
	email, ok := normalizeEmail(email)
	if !ok || password == "" || len(password) > 72 {
		return AuthResult{}, ErrInvalidCredentials
	}
	user, err := s.users.FindByEmail(ctx, email)
	if errors.Is(err, repository.ErrNotFound) {
		_ = bcrypt.CompareHashAndPassword(s.dummyPasswordHash, []byte(password))
		return AuthResult{}, ErrInvalidCredentials
	}
	if err != nil {
		return AuthResult{}, err
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		return AuthResult{}, ErrInvalidCredentials
	}
	return s.result(user)
}

func (s *Service) Me(ctx context.Context, userID string) (model.User, error) {
	user, err := s.users.FindByID(ctx, userID)
	if errors.Is(err, repository.ErrNotFound) {
		return model.User{}, ErrUserNotFound
	}
	return user, err
}

func (s *Service) result(user model.User) (AuthResult, error) {
	value, err := s.tokens.Issue(user.ID, user.Email)
	if err != nil {
		return AuthResult{}, err
	}
	return AuthResult{Token: value, User: user}, nil
}

func normalizeEmail(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) == 0 || len(value) > 255 || strings.ContainsAny(value, "\r\n") {
		return "", false
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value {
		return "", false
	}
	return value, true
}
