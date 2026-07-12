package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	values := map[string]string{
		"AUTH_SERVICE_PORT": "8081",
		"AUTH_DATABASE_URL": "user:pass@tcp(mysql:3306)/auth_db?parseTime=true",
		"JWT_SECRET":        strings.Repeat("s", 32),
		"JWT_EXPIRY":        "2h",
	}
	cfg, err := load(func(key string) string { return values[key] })
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Address() != ":8081" || cfg.JWTExpiry != 2*time.Hour {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	tests := []map[string]string{
		{},
		{"AUTH_SERVICE_PORT": "no", "AUTH_DATABASE_URL": "dsn", "JWT_SECRET": strings.Repeat("s", 32)},
		{"AUTH_SERVICE_PORT": "8081", "AUTH_DATABASE_URL": "dsn", "JWT_SECRET": "short"},
		{"AUTH_SERVICE_PORT": "8081", "AUTH_DATABASE_URL": "dsn", "JWT_SECRET": strings.Repeat("s", 32), "JWT_EXPIRY": "0s"},
	}
	for _, values := range tests {
		if _, err := load(func(key string) string { return values[key] }); err == nil {
			t.Fatalf("expected error for values: %#v", values)
		}
	}
}
