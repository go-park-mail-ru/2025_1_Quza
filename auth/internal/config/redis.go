package config

type Redis struct {
	Address     []string `yaml:"address"`
	Username    string   `yaml:"username"`
	Password    string   `yaml:"password"`
	ClusterMode bool     `yaml:"cluster_mode"`
	DB          int      `yaml:"db"`
	MaxRetry    int      `yaml:"max_retry"`
}
