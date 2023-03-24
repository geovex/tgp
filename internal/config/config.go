package config

import (
	"os"

	"github.com/BurntSushi/toml"
)

var defaultConfigData = `
listen_url = "0.0.0.0:6666"
#secret = "dd000102030405060708090a0b0c0d0e0f"
socks5 = "127.0.0.1:9050"
[users]
1 = "dd000102030405060708090a0b0c0d0e0f"
2 = "dd101112131415161718191a1b1c1d1e1f"
`

type Config struct {
	Listen_Url string
	Secret     *string
	Socks5     *string
	Users      *map[string]string
}

func ReadConfig(path string) (*Config, error) {
	var configData []byte
	var config Config
	configData, err := os.ReadFile(os.Args[1])
	if err != nil {
		return nil, err
	}
	_, err = toml.Decode(string(configData), &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func DefaultConfig() *Config {
	var config Config
	_, err := toml.Decode(defaultConfigData, &config)
	if err != nil {
		panic(err)
	}
	return &config
}
