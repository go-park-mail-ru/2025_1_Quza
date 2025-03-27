package tests

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/cache/redis"
	redisMocks "github.com/go-park-mail-ru/2025_1_Quza/auth/internal/cache/redis/mocks"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/model"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/repository"
	repoMocks "github.com/go-park-mail-ru/2025_1_Quza/auth/internal/repository/mocks"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/service"
	"github.com/gojuno/minimock/v3"
	"github.com/stretchr/testify/require"
)

func TestGetByName(t *testing.T) {
	t.Parallel()
	type AuthCacheMockFunc func(mc *minimock.Controller) redis.UserCacheInterface
	type AuthStorageMockFunc func(mc *minimock.Controller) repository.UserRepositoryInterface

	type args struct {
		ctx  context.Context
		name string
	}

	var (
		ctx     = context.Background()
		mc      = minimock.NewController(t)
		nameVal = gofakeit.Name()
		user    = model.User{
			ID:       int(gofakeit.Int64()),
			Name:     nameVal,
			Email:    "user@example.com",
			Password: "password",
			Role:     "USER",
		}
		storageErr     = errors.New("storage error")
		cacheCreateErr = errors.New("cache create error")
	)

	tests := []struct {
		name            string
		args            args
		expectedUser    *model.User
		expectedErr     error
		authCacheMock   AuthCacheMockFunc
		authStorageMock AuthStorageMockFunc
	}{
		{
			name: "cache hit: user found in cache",
			args: args{
				ctx:  ctx,
				name: nameVal,
			},
			expectedUser: &user,
			expectedErr:  nil,
			authCacheMock: func(mc *minimock.Controller) redis.UserCacheInterface {
				mock := redisMocks.NewUserCacheInterfaceMock(mc)
				// Симулируем успешное получение пользователя из кэша.
				mock.GetByNameMock.Expect(ctx, nameVal).Return(&user, nil)
				return mock
			},
			authStorageMock: func(mc *minimock.Controller) repository.UserRepositoryInterface {
				// Хранилище не вызывается при кэш-хите.
				return repoMocks.NewUserRepositoryInterfaceMock(mc)
			},
		},
		{
			name: "cache miss: user not in cache, found in storage, кэширование прошло успешно",
			args: args{
				ctx:  ctx,
				name: nameVal,
			},
			expectedUser: &user,
			expectedErr:  nil,
			authCacheMock: func(mc *minimock.Controller) redis.UserCacheInterface {
				mock := redisMocks.NewUserCacheInterfaceMock(mc)
				// Симулируем отсутствие пользователя в кэше.
				mock.GetByNameMock.Expect(ctx, nameVal).Return(nil, model.ErrUserNotFound)
				// После получения из хранилища ожидаем успешное кэширование.
				mock.CreateMock.Expect(ctx, user.ID, user).Return(nil)
				return mock
			},
			authStorageMock: func(mc *minimock.Controller) repository.UserRepositoryInterface {
				mock := repoMocks.NewUserRepositoryInterfaceMock(mc)
				// Возвращаем пользователя из хранилища.
				mock.GetUserByNameMock.Expect(ctx, nameVal).Return(&user, nil)
				return mock
			},
		},
		{
			name: "cache miss: user not in cache, storage возвращает ошибку",
			args: args{
				ctx:  ctx,
				name: nameVal,
			},
			expectedUser: nil,
			expectedErr:  fmt.Errorf("error getting user profile: %w", storageErr),
			authCacheMock: func(mc *minimock.Controller) redis.UserCacheInterface {
				mock := redisMocks.NewUserCacheInterfaceMock(mc)
				// Симулируем отсутствие пользователя в кэше.
				mock.GetByNameMock.Expect(ctx, nameVal).Return(nil, model.ErrUserNotFound)
				return mock
			},
			authStorageMock: func(mc *minimock.Controller) repository.UserRepositoryInterface {
				mock := repoMocks.NewUserRepositoryInterfaceMock(mc)
				// Возвращаем ошибку из хранилища.
				mock.GetUserByNameMock.Expect(ctx, nameVal).Return(nil, storageErr)
				return mock
			},
		},
		{
			name: "cache miss: user найден в хранилище, но ошибка кэширования",
			args: args{
				ctx:  ctx,
				name: nameVal,
			},
			expectedUser: nil,
			expectedErr:  fmt.Errorf("error caching user profile: %w", cacheCreateErr),
			authCacheMock: func(mc *minimock.Controller) redis.UserCacheInterface {
				mock := redisMocks.NewUserCacheInterfaceMock(mc)
				// Симулируем отсутствие пользователя в кэше.
				mock.GetByNameMock.Expect(ctx, nameVal).Return(nil, model.ErrUserNotFound)
				// Кэширование завершилось ошибкой.
				mock.CreateMock.Expect(ctx, user.ID, user).Return(cacheCreateErr)
				return mock
			},
			authStorageMock: func(mc *minimock.Controller) repository.UserRepositoryInterface {
				mock := repoMocks.NewUserRepositoryInterfaceMock(mc)
				// Возвращаем пользователя из хранилища.
				mock.GetUserByNameMock.Expect(ctx, nameVal).Return(&user, nil)
				return mock
			},
		},
	}

	defer mc.Finish()

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cacheMock := tt.authCacheMock(mc)
			storageMock := tt.authStorageMock(mc)
			svc := service.NewUserService(storageMock, cacheMock)

			gotUser, err := svc.GetByName(tt.args.ctx, tt.args.name)
			if tt.expectedErr != nil {
				require.EqualError(t, err, tt.expectedErr.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedUser, gotUser)
			}
		})
	}
}
