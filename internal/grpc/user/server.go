package user

import (
	"context"
	ssov1 "github.com/DarkhanOmirbay/proto/proto/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type User interface {
	EditProfile(ctx context.Context, userId int64, user ssov1.User) (string, *ssov1.User, error)
	DeleteAccount(ctx context.Context, userId int64) (string, error)
	ShowProfile(ctx context.Context, userId int64) (*ssov1.User, error)
}
type serverAPI struct {
	ssov1.UnimplementedUserProfileServer
	user User
}

func Register(grpcServer *grpc.Server, u User) {
	ssov1.RegisterUserProfileServer(grpcServer, &serverAPI{user: u})
}
func (s *serverAPI) EditProfile(ctx context.Context, in *ssov1.EditProfileRequest) (*ssov1.EditProfileResponse, error) {
	if in.Id == 0 || in.Id < 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	msg, user, err := s.user.EditProfile(ctx, in.Id, *in.User)
	if err != nil {
		return nil, err
	}
	return &ssov1.EditProfileResponse{Msg: msg, UpdatedUser: user}, nil
}
func (s *serverAPI) DeleteAccount(ctx context.Context, in *ssov1.DeleteAccountRequest) (*ssov1.DeleteAccountResponse, error) {
	if in.Id == 0 || in.Id < 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	msg, err := s.user.DeleteAccount(ctx, in.Id)
	if err != nil {
		return nil, err
	}
	return &ssov1.DeleteAccountResponse{Msg: msg}, nil
}
func (s *serverAPI) ShowProfile(ctx context.Context, in *ssov1.ShowProfileRequest) (*ssov1.ShowProfileResponse, error) {
	if in.Id == 0 || in.Id < 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	user, err := s.user.ShowProfile(ctx, in.Id)
	if err != nil {
		return nil, err
	}
	return &ssov1.ShowProfileResponse{User: user}, nil
}
