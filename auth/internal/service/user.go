package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/cache/redis"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/model"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/repository"
	"github.com/go-park-mail-ru/2025_1_Quza/platform/pkg/logger"
)

type UserService struct {
	cache   redis.UserCacheInterface
	storage repository.UserRepositoryInterface
}

func NewUserService(
	storage repository.UserRepositoryInterface,
	cache redis.UserCacheInterface,
) IUserService {
	return &UserService{
		storage: storage,
		cache:   cache,
	}
}

func (s UserService) GetByName(ctx context.Context, name string) (*model.User, error) {
	var (
		userProfile *model.User
		errCache    error
	)

	userProfile, errCache = s.cache.GetByName(ctx, name)
	if errCache != nil {
		if errors.Is(errCache, model.ErrUserNotFound) {

			var err error
			userProfile, err = s.storage.GetUserByName(ctx, name)
			if err != nil {
				return nil, fmt.Errorf("error getting user profile: %w", err)
			}

			if err = s.cache.Create(ctx, userProfile.ID, *userProfile); err != nil {
				return nil, fmt.Errorf("error caching user profile: %w", err)
			}
		}
	}

	return userProfile, nil
}

func (s UserService) Delete(ctx context.Context, userID int) error {
	if err := s.storage.Delete(ctx, userID); err != nil {
		return err
	}

	return nil
}

func (s UserService) Create(ctx context.Context, user model.User) (*int, error) {
	var id int
	id, err := s.storage.Save(ctx, user)
	if err != nil {
		return nil, err
	}

	if err = s.cache.Create(ctx, id, user); err != nil {
		logger.Info("REDIS", "failed to create user")
	}

	return &id, nil
}

func (s UserService) GetById(ctx context.Context, id int) (*model.User, error) {
	var (
		userProfile *model.User
		errCache    error
		err         error
	)

	userProfile, errCache = s.cache.GetById(ctx, id)
	if errCache != nil {
		if errors.Is(errCache, model.ErrUserNotFound) {

			userProfile, err = s.storage.GetUserById(ctx, id)
			if err != nil {
				return nil, fmt.Errorf("error getting user profile: %w", err)
			}

			if err = s.cache.Create(ctx, userProfile.ID, *userProfile); err != nil {
				return nil, fmt.Errorf("error caching user profile: %w", err)
			}
		}
	}

	return userProfile, nil
}

func (s UserService) Update(ctx context.Context, userUpdate model.User) error {
	if err := s.storage.Update(ctx, userUpdate); err != nil {
		return err
	}

	return nil
}
