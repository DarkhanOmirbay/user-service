package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sso/internal/domain/models"
	"time"
)

var (
	ErrDuplicateEmail = errors.New("duplicate email")
	ErrRecordNotFound = errors.New("record not found")
	ErrEditConflict   = errors.New("edit conflict")
)

type UserStorage struct {
	db *sql.DB
}

func (us *UserStorage) GetUser(ctx context.Context, id int64) (*models.User, error) {
	const op = "domain.storage.User"
	fail := func(e error) error {
		return fmt.Errorf("%s: %w", op, e)
	}
	stmt, err := us.db.Prepare(`SELECT * FROM users WHERE id = $1`)
	if err != nil {
		return nil, fail(err)
	}
	var User models.User
	row := stmt.QueryRowContext(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fail(sql.ErrNoRows)
	}
	err = row.Scan(&User.ID, &User.Fname, &User.Lname, &User.Email, &User.PasswordHash.Hash, &User.Role, &User.Activated)
	if err != nil {
		return nil, fail(err)
	}
	return &User, nil
}
func (us *UserStorage) UpdateUser(ctx context.Context, user models.User) error {
	query := `UPDATE users SET fname=$1,lname=$2,email=$3,password_hash=$4 WHERE id=$5`
	args := []any{user.Fname, user.Lname, user.Email, user.PasswordHash.Hash, user.ID}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := us.db.QueryRowContext(ctx, query, args...)
	if err != nil {
		return err.Err()
	}
	return nil
}

func (us *UserStorage) DeleteUser(ctx context.Context, userId int64) error {
	query := `DELETE FROM users WHERE id=$1`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := us.db.ExecContext(ctx, query, userId)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrRecordNotFound
	}
	return nil
}
