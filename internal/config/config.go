package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const defaultJWTExpiry = 24 * time.Hour

type Config struct {
	Port        int
	DatabaseURL string
	JWTSecret   string
	JWTExpiry   time.Duration
}

func Load() (Config, error) {
	return load(os.Getenv)
}

func load(getenv func(string) string) (Config, error) {
	portValue := strings.TrimSpace(getenv("AUTH_SERVICE_PORT"))
	databaseURL := strings.TrimSpace(getenv("AUTH_DATABASE_URL"))
	jwtSecret := getenv("JWT_SECRET")

	var missing []string
	if portValue == "" {
		missing = append(missing, "AUTH_SERVICE_PORT")
	}
	if databaseURL == "" {
		missing = append(missing, "AUTH_DATABASE_URL")
	}
	if jwtSecret == "" {
		missing = append(missing, "JWT_SECRET")
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	port, err := strconv.Atoi(portValue)
	if err != nil || port < 1 || port > 65535 {
		return Config{}, errors.New("AUTH_SERVICE_PORT must be a number from 1 to 65535")
	}
	if len(jwtSecret) < 32 {
		return Config{}, errors.New("JWT_SECRET must be at least 32 characters")
	}

	expiry := defaultJWTExpiry
	if value := strings.TrimSpace(getenv("JWT_EXPIRY")); value != "" {
		expiry, err = time.ParseDuration(value)
		if err != nil || expiry <= 0 {
			return Config{}, errors.New("JWT_EXPIRY must be a positive Go duration")
		}
	}

	return Config{Port: port, DatabaseURL: databaseURL, JWTSecret: jwtSecret, JWTExpiry: expiry}, nil
}

func (c Config) Address() string {
	return fmt.Sprintf(":%d", c.Port)
}
