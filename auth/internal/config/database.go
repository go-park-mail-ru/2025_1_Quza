package config

import (
	"time"
)

const (
	DefaultConnectionLifetime = 10 * time.Minute
)

type Database struct {
	DSN                   string        `yaml:"dsn"`
	MaxIdleConnections    int           `yaml:"max_idle_conn"`
	MaxOpenConnections    int           `yaml:"max_open_conn"`
	MaxConnectionLifetime time.Duration `yaml:"max_connection_lifetime"`
}
