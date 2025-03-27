package config

import (
	"time"
)

const (
	DefaultRefreshTokenExpiration = 24 * time.Hour
	DefaultAccessTokenExpiration  = 1 * time.Hour
)

type Auth struct {
	SecretKey          string        `yaml:"secret_key"`
	AccessTokenExpire  time.Duration `yaml:"access_token_expire"`
	RefreshTokenExpire time.Duration `yaml:"refresh_token_expire"`
}
