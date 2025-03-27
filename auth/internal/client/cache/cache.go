package cache

import (
	"context"
	"time"
)

// RedisCache интерфейс для работы с кэшем.
type RedisCache interface {
	HashSet(ctx context.Context, key string, values interface{}) error
	Set(ctx context.Context, key string, value interface{}) error
	HGetAll(ctx context.Context, key string) ([]interface{}, error)
	Get(ctx context.Context, key string) (interface{}, error)
	Expire(ctx context.Context, key string, duration time.Duration) error
	Ping(ctx context.Context) error
}
