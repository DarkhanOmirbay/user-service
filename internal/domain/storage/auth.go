package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	_ "github.com/lib/pq"
	"sso/internal/domain/models"
)

type AuthStorage struct {
	db *sql.DB
}

func (s *AuthStorage) SaveUser(ctx context.Context, fname string, lname string, email string, passHash []byte) (int64, error) {
	const op = "domain.storage.SaveUser"
	fail := func(e error) error {
		return fmt.Errorf("%s: %w", op, e)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	defer tx.Rollback()
	if err != nil {
		return 0, fail(err)
	}

	stmt, err := s.db.Prepare("INSERT INTO users(fname,lname, email, password_hash,user_role,activated) VALUES($1, $2, $3, $4, $5,$6) RETURNING id")
	if err != nil {
		return 0, fail(err)
	}

	var id int64
	err = stmt.QueryRowContext(ctx, fname, lname, email, passHash, "user", false).Scan(&id)
	if err != nil {
		return 0, fail(err)
	}

	err = tx.Commit()
	if err != nil {
		return 0, fail(err)
	}

	return id, nil
}

func (s *AuthStorage) GetUserByEmail(ctx context.Context, email string) (models.User, error) {
	const op = "storage.User"

	stmt, err := s.db.Prepare("SELECT id, fname,lname, email, password_hash, activated FROM users WHERE email = $1")
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, email)

	var user models.User
	err = row.Scan(&user.ID, &user.Fname, &user.Lname, &user.Email, &user.PasswordHash.Hash, &user.Activated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}

		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

func (s *AuthStorage) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "storage.sqlite.IsAdmin"
	stmt, err := s.db.Prepare("SELECT user_role FROM users WHERE id = $1")
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return false, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		default:
			return false, fmt.Errorf("%s: %w", op, err)
		}
	}

	row := stmt.QueryRowContext(ctx, userID)

	var role string
	err = row.Scan(&role)
	if err != nil {
		println(fmt.Errorf("%s: %w", op, ErrUserNotFound))
		return false, err
	}

	isRoleAdmin := role == "admin"
	return isRoleAdmin, nil
}
