package service

import (
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/cache/redis"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/config"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/repository"
)

type Services struct {
	Auth IAuthorizationService
	User IUserService
}

type Deps struct {
	Version    string
	Repository repository.Repositories
	Cache      redis.UserCacheInterface
	Config     config.Auth
}

func NewServices(deps Deps) Services {
	return Services{
		Auth: NewAuthService(deps.Cache, deps.Repository.User, deps.Repository.AccessPolicies, deps.Config),
		User: NewUserService(deps.Repository.User, deps.Cache),
	}
}
