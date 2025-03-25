package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/cache/redis"
	redisMocks "github.com/go-park-mail-ru/2025_1_Quza/auth/internal/cache/redis/mocks"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/repository"
	repoMocks "github.com/go-park-mail-ru/2025_1_Quza/auth/internal/repository/mocks"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/service"
	"github.com/gojuno/minimock/v3"
	"github.com/stretchr/testify/require"
)

func TestDelete(t *testing.T) {
	t.Parallel()
	type (
		AuthCacheMockFunc   func(mc *minimock.Controller) redis.UserCacheInterface
		AuthStorageMockFunc func(mc *minimock.Controller) repository.UserRepositoryInterface
	)

	var (
		ctx       = context.Background()
		mc        = minimock.NewController(t)
		userID    = int(gofakeit.Int64())
		errDelete = errors.New("error delete")
	)

	// Dummy cache-мок, т.к. функция Delete не взаимодействует с кэшем.
	dummyCache := func(mc *minimock.Controller) redis.UserCacheInterface {
		return redisMocks.NewUserCacheInterfaceMock(mc)
	}

	tests := []struct {
		name            string
		ctx             context.Context
		userID          int
		err             error
		authStorageMock AuthStorageMockFunc
		authCacheMock   AuthCacheMockFunc
	}{
		{
			name:   "успешное удаление",
			ctx:    ctx,
			userID: userID,
			err:    nil,
			authStorageMock: func(mc *minimock.Controller) repository.UserRepositoryInterface {
				mock := repoMocks.NewUserRepositoryInterfaceMock(mc)
				mock.DeleteMock.Expect(ctx, userID).Return(nil)
				return mock
			},
			authCacheMock: dummyCache,
		},
		{
			name:   "ошибка удаления",
			ctx:    ctx,
			userID: userID,
			err:    errDelete,
			authStorageMock: func(mc *minimock.Controller) repository.UserRepositoryInterface {
				mock := repoMocks.NewUserRepositoryInterfaceMock(mc)
				mock.DeleteMock.Expect(ctx, userID).Return(errDelete)
				return mock
			},
			authCacheMock: dummyCache,
		},
	}

	defer mc.Finish()

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			storageMock := tt.authStorageMock(mc)
			cacheMock := tt.authCacheMock(mc)
			srv := service.NewUserService(storageMock, cacheMock)

			err := srv.Delete(tt.ctx, tt.userID)
			if tt.err != nil {
				require.EqualError(t, err, tt.err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
