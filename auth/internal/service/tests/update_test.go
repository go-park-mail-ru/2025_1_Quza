package tests

import (
	"context"
	"errors"
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

func TestUpdate(t *testing.T) {
	t.Parallel()
	type (
		AuthCacheMockFunc   func(mc *minimock.Controller) redis.UserCacheInterface
		AuthStorageMockFunc func(mc *minimock.Controller) repository.UserRepositoryInterface
	)

	type args struct {
		ctx  context.Context
		user model.User
	}

	var (
		ctx          = context.Background()
		mc           = minimock.NewController(t)
		name         = gofakeit.Name()
		correctEmail = "Dr.Pepper@gmail.com"
		password     = "12345678910"
		user         = model.User{
			Name:     name,
			Email:    correctEmail,
			Password: password,
			Role:     "USER",
		}
		errUpdate = errors.New("error update")
	)

	// Dummy cache-мок, т.к. функция Update не использует кэш.
	dummyCache := func(mc *minimock.Controller) redis.UserCacheInterface {
		return redisMocks.NewUserCacheInterfaceMock(mc)
	}

	tests := []struct {
		name            string
		args            args
		err             error
		authStorageMock AuthStorageMockFunc
		authCacheMock   AuthCacheMockFunc
	}{
		{
			name: "успешное обновление",
			args: args{
				ctx:  ctx,
				user: user,
			},
			err: nil,
			authStorageMock: func(mc *minimock.Controller) repository.UserRepositoryInterface {
				mock := repoMocks.NewUserRepositoryInterfaceMock(mc)
				mock.UpdateMock.Expect(ctx, user).Return(nil)
				return mock
			},
			authCacheMock: dummyCache,
		},
		{
			name: "ошибка обновления",
			args: args{
				ctx:  ctx,
				user: user,
			},
			err: errUpdate,
			authStorageMock: func(mc *minimock.Controller) repository.UserRepositoryInterface {
				mock := repoMocks.NewUserRepositoryInterfaceMock(mc)
				mock.UpdateMock.Expect(ctx, user).Return(errUpdate)
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

			err := srv.Update(tt.args.ctx, tt.args.user)
			if tt.err != nil {
				require.EqualError(t, err, tt.err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
