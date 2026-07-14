package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"auction/auth/internal/middleware"
	"auction/auth/internal/service"
)

const maxBodyBytes = 1 << 20

type Handler struct {
	auth service.AuthService
}

func New(auth service.AuthService, authMiddleware *middleware.Auth) http.Handler {
	h := &Handler{auth: auth}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/register", h.register)
	mux.HandleFunc("POST /api/auth/login", h.login)
	mux.Handle("POST /api/auth/logout", authMiddleware.Protect(http.HandlerFunc(h.logout)))
	mux.Handle("GET /api/auth/me", authMiddleware.Protect(http.HandlerFunc(h.me)))
	mux.Handle("POST /api/auth/change-password", authMiddleware.Protect(http.HandlerFunc(h.changePassword)))
	return mux
}

type registerRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var input registerRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := h.auth.Register(r.Context(), input.Name, input.Email, input.Password)
	if errors.Is(err, service.ErrInvalidInput) {
		writeError(w, http.StatusBadRequest, "invalid_input", "name, email, or password is invalid")
		return
	}
	if errors.Is(err, service.ErrEmailConflict) {
		writeError(w, http.StatusConflict, "email_conflict", "email already exists")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var input loginRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := h.auth.Login(r.Context(), input.Email, input.Password)
	if errors.Is(err, service.ErrInvalidCredentials) {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) logout(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}
	user, err := h.auth.Me(r.Context(), claims.Subject)
	if errors.Is(err, service.ErrUserNotFound) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}
	var input changePasswordRequest
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	if err := h.auth.ChangePassword(r.Context(), claims.Subject, input.CurrentPassword, input.NewPassword); err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidInput):
			writeError(w, http.StatusBadRequest, "invalid_input", "current password and new password are invalid")
		case errors.Is(err, service.ErrInvalidCredentials):
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "current password is incorrect")
		case errors.Is(err, service.ErrUserNotFound):
			writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		default:
			writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
