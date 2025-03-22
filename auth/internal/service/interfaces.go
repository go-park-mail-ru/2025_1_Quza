package service

import (
	"context"

	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/model"
)

type IUserService interface {
	Create(ctx context.Context, user model.User) (*int, error)
	Delete(ctx context.Context, id int) error
	Update(ctx context.Context, userUpdate model.User) error
	GetById(ctx context.Context, id int) (*model.User, error)
	GetByName(ctx context.Context, name string) (*model.User, error)
}

type IAuthorizationService interface {
	Login(ctx context.Context, user model.User) (*string, error)
	GetAccessToken(ctx context.Context, refreshToken string) (*string, error)
	GetRefreshToken(ctx context.Context, refreshToken string) (*string, error)
	Check(ctx context.Context, address string) error
}
