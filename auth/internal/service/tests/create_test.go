package tests

import (
	"context"
	"errors"
	"testing"

	redisMocks "github.com/go-park-mail-ru/2025_1_Quza/auth/internal/cache/redis/mocks"
	repoMocks "github.com/go-park-mail-ru/2025_1_Quza/auth/internal/repository/mocks"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/service"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/cache/redis"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/model"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/repository"
	"github.com/gojuno/minimock/v3"
	"github.com/stretchr/testify/require"
)

func TestCreate(t *testing.T) {
	t.Parallel()
	type (
		AuthCacheMockFunc   func(mc *minimock.Controller) redis.UserCacheInterface
		AuthStorageMockFunc func(mc *minimock.Controller) repository.UserRepositoryInterface
	)

	type args struct {
		ctx context.Context
		req model.User
	}

	var (
		ctx          = context.Background()
		mc           = minimock.NewController(t)
		name         = gofakeit.Name()
		correctEmail = "Dr.Pepper@gmail.com"
		password     = "12345678910"
		id           = int(gofakeit.Int64())
		errSave      = errors.New("error save")
		user         = model.User{
			Name:     name,
			Email:    correctEmail,
			Password: password,
			Role:     "USER",
		}
	)

	defer mc.Finish()
	tests := []struct {
		name            string
		args            args
		want            *int
		err             error
		authCacheMock   AuthCacheMockFunc
		authStorageMock AuthStorageMockFunc
	}{
		{
			name: "success case",
			args: args{
				ctx: ctx,
				req: user,
			},
			want: &id,
			err:  nil,
			authCacheMock: func(mc *minimock.Controller) redis.UserCacheInterface {
				mock := redisMocks.NewUserCacheInterfaceMock(mc)
				mock.CreateMock.Return(nil)
				return mock
			},
			authStorageMock: func(mc *minimock.Controller) repository.UserRepositoryInterface {
				mock := repoMocks.NewUserRepositoryInterfaceMock(mc)
				mock.SaveMock.Expect(ctx, user).Return(id, nil)
				return mock
			},
		},
		{
			name: "error case",
			args: args{
				ctx: ctx,
				req: user,
			},
			want: &id,
			err:  errSave,
			authCacheMock: func(mc *minimock.Controller) redis.UserCacheInterface {
				mock := redisMocks.NewUserCacheInterfaceMock(mc)
				return mock
			},
			authStorageMock: func(mc *minimock.Controller) repository.UserRepositoryInterface {
				mock := repoMocks.NewUserRepositoryInterfaceMock(mc)
				mock.SaveMock.Expect(ctx, user).Return(id, errSave)
				return mock
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			RepoMock := tt.authStorageMock(mc)
			CacheMock := tt.authCacheMock(mc)
			service := service.NewUserService(RepoMock, CacheMock)

			_, err := service.Create(tt.args.ctx, tt.args.req)
			if tt.err != nil {
				require.EqualError(t, err, tt.err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
