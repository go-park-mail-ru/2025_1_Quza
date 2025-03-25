package redis

import (
	"context"
	"fmt"
	"strconv"
	"time"

	myredis "github.com/go-park-mail-ru/2025_1_Quza/auth/internal/client/cache/redis"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/model"
	"github.com/gomodule/redigo/redis"
)

type cache struct {
	cl myredis.Client
}

func NewRedisCache(cl myredis.Client) UserCacheInterface {
	return &cache{cl: cl}
}

func (c cache) GetByName(ctx context.Context, name string) (*model.User, error) {
	key := name

	userCache, err := c.cl.HGetAll(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("error with get user cache: %w", err)
	}

	if userCache == nil {
		return nil, fmt.Errorf("user cache is nil")
	}

	var user *model.User
	err = redis.ScanStruct(userCache, &user)
	if err != nil {
		return nil, fmt.Errorf("error scanning user profile: %w", err)
	}

	return user, nil
}

func (c cache) GetById(ctx context.Context, id int) (*model.User, error) {
	key := strconv.Itoa(id)

	userCache, err := c.cl.HGetAll(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("error with get user cache: %w", err)
	}

	if userCache == nil {
		return nil, model.ErrUserNotFound
	}

	var user *model.User
	err = redis.ScanStruct(userCache, user)
	if err != nil {
		return nil, fmt.Errorf("error scanning user profile: %w", err)
	}

	return user, nil
}

func (c cache) Create(ctx context.Context, id int, user model.User) error {
	if err := c.cl.HashSet(ctx, strconv.Itoa(id), user); err != nil {
		return fmt.Errorf("failed to hash user: %w", err)
	}

	if err := c.cl.HashSet(ctx, user.Name, user); err != nil {
		return fmt.Errorf("failed to hash user: %w", err)
	}

	if err := c.cl.Expire(ctx, strconv.Itoa(id), 5*time.Minute); err != nil {
		return fmt.Errorf("failed to set expiration for user: %w", err)
	}
	return nil
}
