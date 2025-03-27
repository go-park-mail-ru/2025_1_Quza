package redis

import (
	"context"

	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/model"
)

type UserCacheInterface interface {
	Create(ctx context.Context, id int, user model.User) error
	GetById(ctx context.Context, id int) (*model.User, error)
	GetByName(ctx context.Context, name string) (*model.User, error)
}
