package config

import "time"

const (
	RefreshTokenExpiration = 24 * time.Hour
	AccessTokenExpiration  = 1 * time.Hour
)

type AUTH struct {
	SecretToken            string `yaml:"secret_token"`
	RefreshTokenExpiration int    `yaml:"refresh_token_expiration"`
	AccessTokenExpiration  int    `yaml:"access_token_expiration"`
}
