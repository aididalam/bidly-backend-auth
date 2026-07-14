package repository

import (
	"context"
	"database/sql"
	"errors"

	"auction/auth/internal/model"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
)

var (
	ErrNotFound      = errors.New("user not found")
	ErrEmailConflict = errors.New("email already exists")
)

type UserRepository interface {
	Create(context.Context, string, string, string) (model.User, error)
	FindByEmail(context.Context, string) (model.User, error)
	FindByID(context.Context, string) (model.User, error)
	UpdatePassword(context.Context, string, string) error
}

type MySQL struct {
	db *sql.DB
}

func NewMySQL(db *sql.DB) *MySQL {
	return &MySQL{db: db}
}

func (r *MySQL) Create(ctx context.Context, name, email, passwordHash string) (model.User, error) {
	user := model.User{ID: uuid.NewString(), Name: name, Email: email, PasswordHash: passwordHash}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO users (id, name, email, password_hash) VALUES (?, ?, ?, ?)`,
		user.ID, user.Name, user.Email, user.PasswordHash,
	)
	if err != nil {
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
			return model.User{}, ErrEmailConflict
		}
		return model.User{}, err
	}
	return r.FindByID(ctx, user.ID)
}

func (r *MySQL) FindByEmail(ctx context.Context, email string) (model.User, error) {
	return scanUser(r.db.QueryRowContext(ctx,
		`SELECT id, name, email, password_hash, created_at, updated_at FROM users WHERE email = ?`, email,
	))
}

func (r *MySQL) FindByID(ctx context.Context, id string) (model.User, error) {
	return scanUser(r.db.QueryRowContext(ctx,
		`SELECT id, name, email, password_hash, created_at, updated_at FROM users WHERE id = ?`, id,
	))
}

func (r *MySQL) UpdatePassword(ctx context.Context, id, passwordHash string) error {
	result, err := r.db.ExecContext(ctx,
		`UPDATE users SET password_hash = ? WHERE id = ?`, passwordHash, id,
	)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return ErrNotFound
	}
	return nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanUser(row rowScanner) (model.User, error) {
	var user model.User
	err := row.Scan(&user.ID, &user.Name, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, ErrNotFound
	}
	if err != nil {
		return model.User{}, err
	}
	return user, nil
}
