package auth

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/domain/storage"
	"sso/internal/sl"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type AuthProvider interface {
	SaveUser(
		ctx context.Context,
		fname string,
		lname string,
		email string,
		passHash []byte,
	) (uid int64, err error)
	GetUserByEmail(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
	App(ctx context.Context, appID int) (models.App, error)
	SaveToken(ctx context.Context, tokenPlainText string, userId int64) (bool, error)
	IsAuthenticated(ctx context.Context, token string) (bool, int64, error)
}

type Auth struct {
	log          *slog.Logger
	authProvider AuthProvider
	tokenTTL     time.Duration
}

func New(
	log *slog.Logger,
	tokenTTL time.Duration,
	ssoProvider AuthProvider,
) *Auth {
	return &Auth{
		log:          log,
		tokenTTL:     tokenTTL,
		authProvider: ssoProvider,
	}
}

func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string,
	appID int,
) (string, error) {
	const op = "Auth.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("username", email),
	)

	log.Info("attempting to login user")

	user, err := a.authProvider.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", sl.Err(err))
			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		a.log.Error("failed to get user", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PasswordHash.Hash, []byte(password)); err != nil {
		a.log.Info("invalid credentials", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.authProvider.App(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully")

	token, err := NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	isSaved, err := a.authProvider.SaveToken(ctx, token, user.ID)
	if err != nil || !isSaved {
		a.log.Warn("token not saved", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

func (a *Auth) RegisterNewUser(ctx context.Context, fname string, lname string, email string, pass string) (int64, error) {
	const op = "Auth.RegisterNewUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash", sl.Err(err))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.authProvider.SaveUser(ctx, fname, lname, email, passHash)
	if err != nil {
		log.Error("failed to save user", sl.Err(err))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (a *Auth) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "Auth.IsAdmin"

	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)

	log.Info("checking if user is admin")

	isAdmin, err := a.authProvider.IsAdmin(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checked if user is admin", slog.Bool("is_admin", isAdmin))

	return isAdmin, nil
}

func (a *Auth) IsAuthenticated(ctx context.Context, token string) (bool, int64, error) {
	const op = "Auth.IsAuthenticated"

	log := a.log.With(
		slog.String("op", op),
		slog.String("token", token),
	)

	log.Info("checking if user is authenticated")

	isAuthenticated, user_id, err := a.authProvider.IsAuthenticated(ctx, token)
	if err != nil {
		return false, 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checked if user is authenticated", slog.Bool("is_authenticated", isAuthenticated))

	return isAuthenticated, user_id, nil
}
