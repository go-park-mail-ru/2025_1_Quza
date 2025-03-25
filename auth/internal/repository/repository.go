package repository

import (
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repositories struct {
	User           UserRepositoryInterface
	AccessPolicies AccessPolicies
}

func NewRepositories(pool *pgxpool.Pool) Repositories {
	return Repositories{
		User:           NewUserRepository(pool),
		AccessPolicies: NewAccessPolicyRepository(),
	}
}
