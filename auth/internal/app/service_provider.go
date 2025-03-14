package app

import (
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/config"
	"github.com/go-park-mail-ru/2025_1_Quza/platform/pkg/logger"
)

type serviceProvider struct {
	version string

	config *config.Config
}

func newServiceProvider() *serviceProvider {
	ServiceProvider := &serviceProvider{}
	return ServiceProvider
}

func (s *serviceProvider) Config() (*config.Config, error) {
	if s.config == nil {
		configs, err := config.NewConfig("config.yml")
		if err != nil {
			logger.Warn("CONFIG", "error init config file", "error", err.Error())
			return nil, err
		}

		s.config = configs
	}

	return s.config, nil
}
