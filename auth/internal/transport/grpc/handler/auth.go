package handler

import (
	"context"
	"fmt"

	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/model"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/service"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/transport/grpc/proto/auth_v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

type AuthController struct {
	auth_v1.UnimplementedAuthServer
	authorizationService service.IAuthorizationService
}

func NewAuthControllerAuthorization(authorizationService service.IAuthorizationService) *AuthController {
	return &AuthController{
		authorizationService: authorizationService,
	}
}

func (c AuthController) Check(ctx context.Context, request *auth_v1.CheckRequest) (*emptypb.Empty, error) {
	if access := c.authorizationService.Check(ctx, request.GetEndpointAddress()); access != nil {
		return &emptypb.Empty{}, access
	}

	return &emptypb.Empty{}, nil
}

func (c AuthController) GetAccessToken(ctx context.Context, request *auth_v1.GetAccessTokenRequest) (*auth_v1.GetAccessTokenResponse, error) {
	accessToken, err := c.authorizationService.GetAccessToken(ctx, request.GetRefreshToken())
	if err != nil {
		return nil, fmt.Errorf("error getting access token: %w", err)
	}

	return &auth_v1.GetAccessTokenResponse{AccessToken: *accessToken}, nil
}

func (c AuthController) GetRefreshToken(ctx context.Context, request *auth_v1.GetRefreshTokenRequest) (*auth_v1.GetRefreshTokenResponse, error) {
	refreshToken, err := c.authorizationService.GetRefreshToken(ctx, request.GetOldRefreshToken())
	if err != nil {
		return nil, fmt.Errorf("could not get refresh token: %w", err)
	}

	return &auth_v1.GetRefreshTokenResponse{RefreshToken: *refreshToken}, nil
}

func (c AuthController) Login(ctx context.Context, request *auth_v1.LoginRequest) (*auth_v1.LoginResponse, error) {
	user := model.User{Name: request.GetUsername(), Password: request.GetPassword()}

	refreshToken, err := c.authorizationService.Login(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	return &auth_v1.LoginResponse{RefreshToken: *refreshToken}, nil
}
