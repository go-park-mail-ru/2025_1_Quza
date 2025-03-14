package app

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/transport/rest"
	"github.com/go-park-mail-ru/2025_1_Quza/platform/pkg/closer"
	"github.com/go-park-mail-ru/2025_1_Quza/platform/pkg/logger"
)

type App struct {
	*serviceProvider
	httpServer *rest.Server
}

func NewApp(ctx context.Context, version string) (*App, error) {
	a := &App{}
	if err := a.initDeps(ctx, version); err != nil {
		return nil, fmt.Errorf("init deps: %w", err)
	}

	return a, nil
}

func (a *App) initServiceProvider(_ context.Context) {
	a.serviceProvider = newServiceProvider()
}

func (a *App) initDeps(ctx context.Context, version string) error {
	a.initServiceProvider(ctx)
	a.serviceProvider.version = version

	inits := []func(context.Context) error{
		a.initConfig,
		a.initLogger,
	}

	var initErrors []error

	for _, f := range inits {
		if err := f(ctx); err != nil {
			initErrors = append(initErrors, err)
		}
	}

	if len(initErrors) > 0 {
		logger.Warn("DI", "init deps failed", initErrors)
		for _, err := range initErrors {
			logger.Warn("DI", "error", err.Error())
		}
		closer.CloseAll()
		closer.Wait()
		return fmt.Errorf("initialization encountered %d errors", len(initErrors))
	}

	return nil
}

func (a *App) initConfig(_ context.Context) error {
	_, err := a.serviceProvider.Config()
	if err != nil {
		return err
	}

	return nil
}

func (a *App) initLogger(_ context.Context) error {
	if a.serviceProvider.config == nil {
		return errors.New("config not initialized")
	}

	logger.InitLogger(logger.Config{
		Level:      a.serviceProvider.config.LOG.Level,
		Format:     a.serviceProvider.config.LOG.Format,
		Filename:   a.serviceProvider.config.LOG.Filename,
		MaxSizeMB:  a.serviceProvider.config.LOG.MaxSizeMB,
		MaxBackups: a.serviceProvider.config.LOG.MaxBackups,
		MaxAgeDays: a.serviceProvider.config.LOG.MaxAgeDays,
		Compress:   a.serviceProvider.config.LOG.Compress,
	})

	logger.Info("Version:\t%s\n", a.serviceProvider.version)

	return nil
}
