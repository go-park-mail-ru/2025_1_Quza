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

func TestGetById(t *testing.T) {
	t.Parallel()
	type (
		AuthCacheMockFunc   func(mc *minimock.Controller) redis.UserCacheInterface
		AuthStorageMockFunc func(mc *minimock.Controller) repository.UserRepositoryInterface
	)

	type args struct {
		ctx context.Context
		id  int
	}

	var (
		ctx   = context.Background()
		mc    = minimock.NewController(t)
		idVal = int(gofakeit.Int64())
		user  = model.User{
			ID:       idVal,
			Name:     gofakeit.Name(),
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
			name: "cache hit: user найден в кэше",
			args: args{
				ctx: ctx,
				id:  idVal,
			},
			expectedUser: &user,
			expectedErr:  nil,
			authCacheMock: func(mc *minimock.Controller) redis.UserCacheInterface {
				mock := redisMocks.NewUserCacheInterfaceMock(mc)
				// Симулируем успешное получение пользователя из кэша.
				mock.GetByIdMock.Expect(ctx, idVal).Return(&user, nil)
				return mock
			},
			authStorageMock: func(mc *minimock.Controller) repository.UserRepositoryInterface {
				// Хранилище не вызывается при кэш-хите.
				return repoMocks.NewUserRepositoryInterfaceMock(mc)
			},
		},
		{
			name: "cache miss: пользователь не найден в кэше, найден в хранилище и успешно закэширован",
			args: args{
				ctx: ctx,
				id:  idVal,
			},
			expectedUser: &user,
			expectedErr:  nil,
			authCacheMock: func(mc *minimock.Controller) redis.UserCacheInterface {
				mock := redisMocks.NewUserCacheInterfaceMock(mc)
				// Симулируем отсутствие пользователя в кэше.
				mock.GetByIdMock.Expect(ctx, idVal).Return(nil, model.ErrUserNotFound)
				// После получения из хранилища кэширование проходит успешно.
				mock.CreateMock.Expect(ctx, user.ID, user).Return(nil)
				return mock
			},
			authStorageMock: func(mc *minimock.Controller) repository.UserRepositoryInterface {
				mock := repoMocks.NewUserRepositoryInterfaceMock(mc)
				// Возвращаем пользователя из хранилища.
				mock.GetUserByIdMock.Expect(ctx, idVal).Return(&user, nil)
				return mock
			},
		},
		{
			name: "cache miss: пользователь не найден в кэше, хранилище возвращает ошибку",
			args: args{
				ctx: ctx,
				id:  idVal,
			},
			expectedUser: nil,
			expectedErr:  fmt.Errorf("error getting user profile: %w", storageErr),
			authCacheMock: func(mc *minimock.Controller) redis.UserCacheInterface {
				mock := redisMocks.NewUserCacheInterfaceMock(mc)
				// Симулируем отсутствие пользователя в кэше.
				mock.GetByIdMock.Expect(ctx, idVal).Return(nil, model.ErrUserNotFound)
				return mock
			},
			authStorageMock: func(mc *minimock.Controller) repository.UserRepositoryInterface {
				mock := repoMocks.NewUserRepositoryInterfaceMock(mc)
				// Хранилище возвращает ошибку.
				mock.GetUserByIdMock.Expect(ctx, idVal).Return(nil, storageErr)
				return mock
			},
		},
		{
			name: "cache miss: пользователь найден в хранилище, но кэширование завершается ошибкой",
			args: args{
				ctx: ctx,
				id:  idVal,
			},
			expectedUser: nil,
			expectedErr:  fmt.Errorf("error caching user profile: %w", cacheCreateErr),
			authCacheMock: func(mc *minimock.Controller) redis.UserCacheInterface {
				mock := redisMocks.NewUserCacheInterfaceMock(mc)
				// Симулируем отсутствие пользователя в кэше.
				mock.GetByIdMock.Expect(ctx, idVal).Return(nil, model.ErrUserNotFound)
				// Кэширование завершается ошибкой.
				mock.CreateMock.Expect(ctx, user.ID, user).Return(cacheCreateErr)
				return mock
			},
			authStorageMock: func(mc *minimock.Controller) repository.UserRepositoryInterface {
				mock := repoMocks.NewUserRepositoryInterfaceMock(mc)
				// Возвращаем пользователя из хранилища.
				mock.GetUserByIdMock.Expect(ctx, idVal).Return(&user, nil)
				return mock
			},
		},
	}

	defer mc.Finish()

	for _, tt := range tests {
		tt := tt // захват переменной для параллельного запуска
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cacheMock := tt.authCacheMock(mc)
			storageMock := tt.authStorageMock(mc)
			svc := service.NewUserService(storageMock, cacheMock)
			gotUser, err := svc.GetById(tt.args.ctx, tt.args.id)
			if tt.expectedErr != nil {
				require.EqualError(t, err, tt.expectedErr.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedUser, gotUser)
			}
		})
	}
}
