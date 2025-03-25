package config

import (
	"github.com/go-park-mail-ru/2025_1_Quza/platform/pkg/config"
	"github.com/go-park-mail-ru/2025_1_Quza/platform/pkg/logger"
)

type Config struct {
	AUTH         Auth          `yaml:"AUTH"`
	REDIS        Redis         `yaml:"REDIS"`
	DB           Database      `yaml:"DB"`
	LOG          Logger        `yaml:"LOG"`
	PasswordSalt string        `yaml:"PasswordSalt"`
	SERVER       Server        `yaml:"SERVER"`
	SWAGGER      SwaggerConfig `yaml:"SWAGGER"`
}

func NewConfig(configPath string) (*Config, error) {
	cfg, err := config.NewConfig[Config](configPath)
	if err != nil {
		logger.Fatal("CONFIG", "Error while loading config", err)
		return nil, err
	}

	if cfg.AUTH.AccessTokenExpire == 0 {
		cfg.AUTH.AccessTokenExpire = DefaultAccessTokenExpiration
	}

	if cfg.AUTH.RefreshTokenExpire == 0 {
		cfg.AUTH.RefreshTokenExpire = DefaultRefreshTokenExpiration
	}

	if cfg.DB.MaxConnectionLifetime == 0 {
		cfg.DB.MaxConnectionLifetime = DefaultConnectionLifetime
	}

	if cfg.LOG.Level == "" {
		cfg.LOG.Level = DefaultLogLevel
	}

	if cfg.LOG.Format == "" {
		cfg.LOG.Format = DefaultFormat
	}

	if cfg.LOG.Filename == "" {
		cfg.LOG.Filename = DefaultFilename
	}

	if cfg.LOG.MaxSizeMB == 0 {
		cfg.LOG.MaxSizeMB = DefaultMaxSizeMB
	}

	if cfg.LOG.MaxBackups == 0 {
		cfg.LOG.MaxBackups = DefaultMaxBackups
	}

	if cfg.LOG.MaxAgeDays == 0 {
		cfg.LOG.MaxAgeDays = DefaultMaxAgeDays
	}

	return cfg, nil
}
