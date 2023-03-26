package config

import (
	"fmt"
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

type config struct {
	Listen_Url string
	Secret     *string
	Socks5     *string
	Users      *map[string]string
}

type Config struct {
	Listen_Url string
	Secret     *string
	Socks5     *string
	Users      *Users
}

func ReadConfig(path string) (*Config, error) {
	var configData []byte
	var c config
	configData, err := os.ReadFile(os.Args[1])
	if err != nil {
		return nil, err
	}
	_, err = toml.Decode(string(configData), &c)
	if err != nil {
		return nil, err
	}
	result, err := configFromParsed(&c)
	if err != nil {
		return result, err
	}
	return result, nil
}

func DefaultConfig() *Config {
	var c config
	_, err := toml.Decode(defaultConfigData, &c)
	if err != nil {
		panic(err)
	}
	result, err := configFromParsed(&c)
	if err != nil {
		panic(err)
	}
	return result
}
func configFromParsed(parsed *config) (c *Config, err error) {
	var userDB *Users
	if c.Users != nil && c.Secret == nil {
		userDB = NewUsersMap(*parsed.Users)
	} else if c.Users == nil && c.Secret != nil {
		userDB = NewUsersSecret(*c.Secret)
	} else {
		return nil, fmt.Errorf("specify either secret or users")
	}
	c = &Config{
		Listen_Url: parsed.Listen_Url,
		Secret:     parsed.Secret,
		Socks5:     parsed.Socks5,
		Users:      userDB,
	}
	return
}
