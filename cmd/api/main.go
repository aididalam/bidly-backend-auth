package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auction/auth/internal/config"
	"auction/auth/internal/handler"
	"auction/auth/internal/middleware"
	"auction/auth/internal/repository"
	"auction/auth/internal/service"
	"auction/auth/internal/token"
	"auction/auth/migrations"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	db, err := sql.Open("mysql", cfg.DatabaseURL)
	if err != nil {
		logger.Error("open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	db.SetConnMaxLifetime(3 * time.Minute)
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)

	startupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(startupCtx); err != nil {
		logger.Error("connect database", "error", err)
		os.Exit(1)
	}
	if err := migrations.Up(startupCtx, db); err != nil {
		logger.Error("run migrations", "error", err)
		os.Exit(1)
	}

	tokens := token.NewManager(cfg.JWTSecret, cfg.JWTExpiry)
	repo := repository.NewMySQL(db)
	authService := service.New(repo, tokens)
	authMiddleware := middleware.NewAuth(tokens)

	server := &http.Server{
		Addr:              cfg.Address(),
		Handler:           handler.New(authService, authMiddleware),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("auth service started", "address", server.Addr)
		serverErrors <- server.ListenAndServe()
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-signals:
		logger.Info("shutdown requested", "signal", sig.String())
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", "error", err)
			os.Exit(1)
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown", "error", err)
		os.Exit(1)
	}
}
