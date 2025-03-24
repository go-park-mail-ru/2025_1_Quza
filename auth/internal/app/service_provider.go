package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Dnlbb/platform_common/pkg/closer"
	myUserCache "github.com/go-park-mail-ru/2025_1_Quza/auth/internal/cache/redis"
	myredis "github.com/go-park-mail-ru/2025_1_Quza/auth/internal/client/cache/redis"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/config"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/repository"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/service"
	"github.com/go-park-mail-ru/2025_1_Quza/platform/pkg/logger"
	"github.com/gomodule/redigo/redis"
	"github.com/jackc/pgx/v5/pgxpool"
)

type serviceProvider struct {
	configs *config.Config
	redis   *redis.Pool
	pgPool  *pgxpool.Pool

	redisClient *myredis.Client

	userCache    *myUserCache.UserCacheInterface
	repositories *repository.Repositories

	services *service.Services
}

func newServiceProvider() *serviceProvider {
	ServiceProvider := &serviceProvider{}
	return ServiceProvider
}

func (s *serviceProvider) Configs() error {
	if s.configs == nil {
		configs, err := config.NewConfig("config.yml")
		if err != nil {
			logger.Warn("CONFIG", "error init config", err)
			return err
		}

		s.configs = configs
	}

	return nil
}

func (s *serviceProvider) RedisPool() (*redis.Pool, error) {

	if s.configs.REDIS.ClusterMode {
		return nil, errors.New("cluster mode not supported: используйте специализированную библиотеку для Redis кластера")
	}

	if len(s.configs.REDIS.Address) == 0 {
		return nil, errors.New("no redis address provided")
	}

	address := s.configs.REDIS.Address[0]

	pool := &redis.Pool{
		MaxIdle:     10,
		MaxActive:   50,
		IdleTimeout: 240 * time.Second,
		Dial: func() (redis.Conn, error) {
			options := []redis.DialOption{
				redis.DialDatabase(s.configs.REDIS.DB),
				redis.DialConnectTimeout(5 * time.Second),
				redis.DialReadTimeout(5 * time.Second),
				redis.DialWriteTimeout(5 * time.Second),
			}

			if s.configs.REDIS.Password != "" {
				options = append(options, redis.DialPassword(s.configs.REDIS.Password))
			}

			return redis.Dial("tcp", address, options...)
		},
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			if time.Since(t) < time.Minute {
				return nil
			}
			_, err := c.Do("PING")
			return err
		},
	}

	closer.Add(pool.Close)

	return pool, nil
}

func (s *serviceProvider) RedisClient() (*myredis.Client, error) {
	if s.redisClient == nil {
		pool, err := s.RedisPool()
		if err != nil {
			logger.Warn("REDIS", "error init redis client", err)
			return nil, err
		}

		cli := myredis.NewClient(pool, s.configs.REDIS)

		s.redisClient = &cli
	}

	return s.redisClient, nil
}

func (s *serviceProvider) UserCache() (*myUserCache.UserCacheInterface, error) {
	if s.userCache == nil {
		cli, err := s.RedisClient()
		if err != nil {
			logger.Warn("REDIS", "error init redis client", err)
			return nil, err
		}

		userCache := myUserCache.NewRedisCache(*cli)

		s.userCache = &userCache
	}

	return s.userCache, nil
}

func (s *serviceProvider) PgxPool() (*pgxpool.Pool, error) {

	poolConfig, err := pgxpool.ParseConfig(s.configs.DB.DSN)
	if err != nil {
		return nil, fmt.Errorf("unable to parse DSN: %v", err)
	}

	poolConfig.MaxConns = int32(s.configs.DB.MaxOpenConnections)
	poolConfig.MinConns = int32(s.configs.DB.MaxIdleConnections)
	poolConfig.MaxConnLifetime = s.configs.DB.MaxConnectionLifetime

	ctx := context.Background()
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %v", err)
	}

	return pool, nil
}

func (s *serviceProvider) Repositories() (*repository.Repositories, error) {
	if s.repositories == nil {
		pool, err := s.PgxPool()
		if err != nil {
			logger.Warn("DB", "error init db", err)
			return nil, err
		}

		repositories := repository.NewRepositories(pool)

		s.repositories = &repositories
	}

	return s.repositories, nil
}
