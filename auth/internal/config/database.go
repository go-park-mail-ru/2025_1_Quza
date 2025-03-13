package config

import (
	"time"
)

const (
	DefaultConnectionLifetime = 10 * time.Minute
)

type Database struct {
	DSN                   string
	MaxIdleConnections    int
	MaxOpenConnections    int
	MaxConnectionLifetime time.Duration
}
