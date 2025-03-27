package repository

import (
	"context"

	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/model"
)

type UserRepositoryInterface interface {
	Save(ctx context.Context, user model.User) (int, error)
	Update(ctx context.Context, update model.User) error
	Delete(ctx context.Context, id int) error
	GetUserById(ctx context.Context, id int) (*model.User, error)
	GetUserByName(ctx context.Context, name string) (*model.User, error)
}

type AccessPolicies interface {
	Check(path string, role string) error
}
