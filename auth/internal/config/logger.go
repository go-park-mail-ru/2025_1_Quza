package config

const (
	DefaultLogLevel   = "DEBUG"
	DefaultFormat     = "text"
	DefaultFilename   = "logs/app.log"
	DefaultMaxSizeMB  = 10
	DefaultMaxBackups = 3
	DefaultMaxAgeDays = 7
)

type Logger struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Filename   string `yaml:"filename"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAgeDays int    `yaml:"max_age_days"`
	Compress   bool   `yaml:"compress"`
}
