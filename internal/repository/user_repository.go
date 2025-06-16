package repository

import (
	"context"
	"database/sql"
	"fmt"
)

type UserRepository interface {
	UserExists(ctx context.Context, username string) (bool, error)
	CreateUser(ctx context.Context, username, email, passwordHash string) error
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	UpdateLastLogin(ctx context.Context, userID string) error
}

type PostgresUserRepository struct {
	db *sql.DB
}

func NewPostgresUserRepository(db *sql.DB) *PostgresUserRepository {
	return &PostgresUserRepository{db: db}
}

func (r *PostgresUserRepository) UserExists(ctx context.Context, username string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)`
	err := r.db.QueryRowContext(ctx, query, username).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}
	return exists, nil
}

func (r *PostgresUserRepository) CreateUser(ctx context.Context, username, email, passwordHash string) error {
	insertQuery := `
		INSERT INTO users (username, email, password_hash, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
	`
	_, err := r.db.ExecContext(ctx, insertQuery, username, email, passwordHash)
	if err != nil {
		return fmt.Errorf("failed to insert user: %w", err)
	}
	return nil
}

func (r *PostgresUserRepository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	var user User
	query := `SELECT id, username, email, password_hash, created_at, updated_at, last_login_at FROM users WHERE username = $1`
	err := r.db.QueryRowContext(ctx, query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil // Пользователь не найден
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}
	return &user, nil
}

func (r *PostgresUserRepository) UpdateLastLogin(ctx context.Context, userID string) error {
	updateLoginQuery := `UPDATE users SET last_login_at = NOW() WHERE id = $1`
	_, err := r.db.ExecContext(ctx, updateLoginQuery, userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}
	return nil
}
