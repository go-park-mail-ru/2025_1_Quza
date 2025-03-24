package handler

import (
	"context"
	"fmt"

	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/service"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/transport/grpc/dto"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/transport/grpc/proto/user_v1"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/transport/grpc/request"
	"google.golang.org/protobuf/types/known/emptypb"
)

type UserController struct {
	user_v1.UnimplementedUserApiServer
	userService service.IUserService
}

func NewUserController(user service.IUserService) *UserController {
	return &UserController{userService: user}
}

func (c *UserController) Create(ctx context.Context, req *user_v1.CreateRequest) (*user_v1.CreateResponse, error) {
	user := dto.ToModelUser(req)

	id, err := c.userService.Create(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("error while creating: %w", err)
	}

	return &user_v1.CreateResponse{Id: int64(id)}, nil
}

func (c *UserController) Delete(ctx context.Context, req *user_v1.DeleteRequest) (*emptypb.Empty, error) {
	id := req.GetId()

	if err := c.userService.Delete(ctx, int(id)); err != nil {
		return &emptypb.Empty{}, fmt.Errorf("deleting user error: %w", err)
	}

	return &emptypb.Empty{}, nil
}

func (c *UserController) GetById(ctx context.Context, req *user_v1.GetRequest_Id) (*user_v1.GetResponse, error) {
	id := request.ID(req)

	userProfile, err := c.userService.GetById(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("error when getUser request: %w", err)
	}

	return dto.ToProtoUserProfile(*userProfile), nil
}

func (c *UserController) GetByName(ctx context.Context, req *user_v1.GetRequest_Username) (*user_v1.GetResponse, error) {
	name, err := request.Name(req)
	if err != nil {
		return nil, err
	}

	userProfile, err := c.userService.GetByName(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("error when getUser request: %w", err)
	}

	return dto.ToProtoUserProfile(*userProfile), nil
}

func (c *UserController) Update(ctx context.Context, req *user_v1.UpdateRequest) (*emptypb.Empty, error) {
	updateUser := dto.ToUpdateUser(req)

	if err := c.userService.Update(ctx, *updateUser); err != nil {
		return &emptypb.Empty{}, fmt.Errorf("error updating user: %w", err)
	}

	return &emptypb.Empty{}, nil
}
