package migrations

import (
	"context"
	"database/sql"
	_ "embed"
)

//go:embed 001_init.up.sql
var initialSchema string

func Up(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, initialSchema)
	return err
}
