package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"sso/internal/domain/models"
	"time"
)

type Token struct {
	Plaintext string    `json:"token"`
	Hash      []byte    `json:"-"`
	UserID    int64     `json:"-"`
	Expiry    time.Time `json:"expiry"`
	Scope     string    `json:"-"`
}

func (s *AuthStorage) SaveToken(ctx context.Context, tokenPlainText string, userId int64) (bool, error) {
	const op = "storage.SaveToken"
	tokenHash := sha256.Sum256([]byte(tokenPlainText))
	fail := func(e error) error {
		return fmt.Errorf("%s: %v", op, e)
	}
	stmt, err := s.db.Prepare(`
								INSERT INTO tokens(hash, user_id, expiry) 
								VALUES ($1, $2, $3)
								`)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return false, fmt.Errorf("%s: %w", op, ErrTokenNotSaved)
		default:
			return false, fmt.Errorf("%s: %w", op, err)
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fail(err)
	}
	defer tx.Rollback()

	row := stmt.QueryRowContext(ctx, tokenHash[:], userId, time.Now().Add(time.Hour))

	if row.Err() != nil {
		return false, fail(err)
	}
	return true, nil
}

func (s *AuthStorage) IsAuthenticated(ctx context.Context, tokenPlainText string) (bool, int64, error) {
	const op = "storage.IsAuthenticated"
	tokenHash := sha256.Sum256([]byte(tokenPlainText))
	stmt, err := s.db.Prepare(`SELECT id,fname,lname,email,password_hash,activated FROM users INNER JOIN tokens t ON users.id = t.user_id WHERE t.hash = $1 AND t.expiry > $2`)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return false, 0, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		default:
			return false, 0, fmt.Errorf("%s: %w", op, err)
		}
	}

	row := stmt.QueryRowContext(ctx, tokenHash[:], time.Now())

	if errors.Is(row.Err(), sql.ErrNoRows) {
		return false, 0, nil
	}

	var user models.User
	err = row.Scan(
		&user.ID,
		&user.Fname,
		&user.Lname,
		&user.Email,
		&user.PasswordHash.Hash,
		&user.Activated,
	)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return false, 0, nil
		default:
			return false, 0, err
		}
	}
	return true, user.ID, nil
}

func (s *AuthStorage) CheckTokens() {
	for {
		queryToGetExpiredUserIds := `
			SELECT u.user_id 
			FROM tokens u 
			WHERE expiry < now()`

		rows, err := s.db.Query(queryToGetExpiredUserIds)
		if err != nil {
			log.Printf("failed to get expired users")
			return
		}

		var userInfos []*models.User
		for rows.Next() {
			var userInfo models.User
			err := rows.Scan(&userInfo.ID)
			if err != nil {
				log.Printf("failed to scan expired user")
				return
			}
			userInfos = append(userInfos, &userInfo)
		}

		queryToDeleteExpiredTokens := `
				DELETE FROM tokens
				WHERE user_id = $1`

		for _, ui := range userInfos {
			_, err := s.db.Exec(queryToDeleteExpiredTokens, ui.ID)
			if err != nil {
				log.Printf("failed to delete expired user with id = %d", ui.ID)
				return
			}
		}

		time.Sleep(time.Minute * 20)
	}
}
