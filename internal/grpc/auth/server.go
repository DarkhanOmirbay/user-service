package auth

import (
	"context"
	"errors"
	ssov1 "github.com/DarkhanOmirbay/proto/proto/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sso/internal/domain/storage"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type Auth interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		appID int,
	) (token string, err error)
	RegisterNewUser(
		ctx context.Context,
		fname string,
		lname string,
		email string,
		password string,
	) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
	IsAuthenticated(
		ctx context.Context,
		token string,
	) (bool, int64, error)
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer // Хитрая штука, о ней ниже
	auth                          Auth
}

func Register(gRPCServer *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPCServer, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(
	ctx context.Context,
	req *ssov1.LoginRequest,
) (*ssov1.LoginResponse, error) {
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}
	if req.GetAppId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "app_id is required")
	}
	token, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword(), int(req.GetAppId()))
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		}
		return nil, status.Error(codes.Internal, "failed to login")
	}
	return &ssov1.LoginResponse{Token: token}, nil
}

func (s *serverAPI) Register(
	ctx context.Context,
	in *ssov1.RegisterRequest,
) (*ssov1.RegisterResponse, error) {
	if in.Fname == "" {
		return nil, status.Error(codes.InvalidArgument, "first name is required")
	}
	if in.Lname == "" {
		return nil, status.Error(codes.InvalidArgument, "last name is required")
	}
	if in.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if in.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	uid, err := s.auth.RegisterNewUser(ctx, in.GetFname(), in.GetLname(), in.GetEmail(), in.GetPassword())
	if err != nil {

		if errors.Is(err, storage.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}

		return nil, status.Error(codes.Internal, "failed to register user")
	}

	return &ssov1.RegisterResponse{UserId: uid}, nil
}

func (s *serverAPI) IsAdmin(
	ctx context.Context,
	in *ssov1.IsAdminRequest,
) (*ssov1.IsAdminResponse, error) {
	if in.UserId == 0 {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	isAdmin, err := s.auth.IsAdmin(ctx, in.GetUserId())
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}

		return nil, status.Error(codes.Internal, "failed to check admin status")
	}

	return &ssov1.IsAdminResponse{IsAdmin: isAdmin}, nil
}

func (s *serverAPI) IsAuthenticated(
	ctx context.Context,
	in *ssov1.IsAuthenticatedRequest,
) (*ssov1.IsAuthenticatedResponse, error) {
	if in.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	isAuthenticated, user_id, err := s.auth.IsAuthenticated(ctx, in.GetToken())
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}

		return nil, status.Error(codes.Internal, "failed to check admin status")
	}

	return &ssov1.IsAuthenticatedResponse{IsAuthenticated: isAuthenticated, UserId: user_id}, nil
}
