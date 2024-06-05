package storage

import (
	"database/sql"
	"errors"
	"fmt"
)

var (
	ErrUserExists    = errors.New("user already exists")
	ErrUserNotFound  = errors.New("user not found")
	ErrAppNotFound   = errors.New("app not found")
	ErrTokenNotSaved = errors.New("token not saved")
)

func NewAuthStorage(dsn string) (*AuthStorage, error) {
	const op = "domain.storage.NewAuthStorage"

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &AuthStorage{db: db}, nil
}

func NewUserStorage(dsn string) (*UserStorage, error) {
	const op = "domain.storage.NewUserInfoStorage"

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &UserStorage{db: db}, nil
}

func (s *AuthStorage) Stop(db *sql.DB) error {
	return s.db.Close()
}
