package migrations

import (
	"context"
	"database/sql"
	_ "embed"
)

//go:embed 001_init.up.sql
var initialSchema string

//go:embed 002_demo_users.up.sql
var demoUsers string

func Up(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, initialSchema); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, demoUsers)
	return err
}
