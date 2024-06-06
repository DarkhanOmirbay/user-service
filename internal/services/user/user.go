package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	ssov1 "github.com/DarkhanOmirbay/proto/proto/gen/go/sso"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/sl"
	"strconv"
	"time"
)

type UserProvider interface {
	GetUser(ctx context.Context, userId int64) (*models.User, error)
	UpdateUser(ctx context.Context, user models.User) error
	DeleteUser(ctx context.Context, userId int64) error
}
type User struct {
	log          *slog.Logger
	userProvider UserProvider
	tokenTTL     time.Duration
}

func New(
	log *slog.Logger, usreProvider UserProvider, tokenTTL time.Duration) *User {
	return &User{
		log:          log,
		userProvider: usreProvider,
		tokenTTL:     tokenTTL,
	}
}
func (u *User) EditProfile(ctx context.Context, userId int64, user ssov1.User) (string, *ssov1.User, error) {
	const op = "User.EditProfile"

	log := u.log.With(slog.String("op", op),
		slog.String("user id ", strconv.FormatInt(userId, 10)))

	updatedUser, err := u.userProvider.GetUser(ctx, userId)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return "Error", nil, sql.ErrNoRows
		default:
			return "Error", nil, fmt.Errorf("%s: %w", op, err)
		}
	}
	if user.Fname != "" {
		updatedUser.Fname = user.Fname
	}
	if user.Lname != "" {
		updatedUser.Lname = user.Lname
	}
	if user.Email != "" {
		updatedUser.Email = user.Email
	}
	if user.Password != "" {
		passHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Error("failed to generate password hash", sl.Err(err))

			return "", nil, fmt.Errorf("%s: %w", op, err)
		}
		updatedUser.PasswordHash.Hash = passHash
	}
	err = u.userProvider.UpdateUser(ctx, *updatedUser)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", op, err)
	}
	return "user updated succesfully", &user, nil
}
func (u *User) DeleteAccount(ctx context.Context, userId int64) (string, error) {
	err := u.userProvider.DeleteUser(ctx, userId)
	if err != nil {
		return "error", err
	}
	return "user deleted", nil
}
func (u *User) ShowProfile(ctx context.Context, userID int64) (*ssov1.User, error) {
	user, err := u.userProvider.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	user1 := &ssov1.User{Fname: user.Fname, Lname: user.Lname, Email: user.Email, Password: ""}
	return user1, nil
}
