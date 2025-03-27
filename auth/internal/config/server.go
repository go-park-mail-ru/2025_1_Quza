package config

type HTTP struct {
	Host string `yaml:"host"`
	Port string `yaml:"port"`
}
type GRPC struct {
	Host string `yaml:"host"`
	Port string `yaml:"port"`
}
type Server struct {
	HTTP HTTP `yaml:"http"`
	GRPC GRPC `yaml:"grpc"`
}
