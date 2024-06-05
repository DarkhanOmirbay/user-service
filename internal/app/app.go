package app

import (
	"log/slog"
	grpcapp "sso/internal/app/grpc"
	"sso/internal/domain/storage"
	"sso/internal/services/auth"
	"sso/internal/services/user"
	"time"
)

type App struct {
	GRPCServer *grpcapp.App
}

func New(
	log *slog.Logger,
	grpcPort int,
	dsn string,
	tokenTTL time.Duration,
) *App {

	authStorage, err := storage.NewAuthStorage(dsn)
	if err != nil {
		panic(err)
	}

	userStorage, err := storage.NewUserStorage(dsn)
	if err != nil {
		panic(err)
	}

	authService := auth.New(log, tokenTTL, authStorage)

	userService := user.New(log, userStorage, tokenTTL)

	grpcApp := grpcapp.New(log, authService, userService, grpcPort)

	go authStorage.CheckTokens()
	return &App{
		GRPCServer: grpcApp,
	}
}
