package config

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

var defaultConfigData = `
listen_url = "0.0.0.0:6666"
#secret = "dd000102030405060708090a0b0c0d0e0f"
socks5 = "127.0.0.1:9050"
# For now empty password is not allowed. because of https://github.com/golang/go/issues/57285
user = "test"
password = "test"
[users]
1 = "dd000102030405060708090a0b0c0d0e0f"
2 = "dd101112131415161718191a1b1c1d1e1f"
`

type parsedConfig struct {
	Listen_Url  string
	Secret      *string
	Socks5      *string
	Socks5_user *string
	Socks5_pass *string
	Users       *map[string]string
}

type Config struct {
	Listen_Url  string
	Secret      *string
	Socks5      *string
	Socks5_user *string
	Socks5_pass *string
	Users       *Users
}

func ReadConfig(path string) (*Config, error) {
	var c parsedConfig
	_, err := toml.DecodeFile(path, &c)
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
	var c parsedConfig
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
func configFromParsed(parsed *parsedConfig) (*Config, error) {
	var userDB *Users
	if parsed.Users != nil && parsed.Secret == nil {
		userDB = NewUsersMap(*parsed.Users)
	} else if parsed.Users == nil && parsed.Secret != nil {
		userDB = NewUsersSecret(*parsed.Secret)
	} else {
		return nil, fmt.Errorf("specify either secret or users")
	}
	if (parsed.Socks5_pass == nil && parsed.Socks5_user != nil) ||
		(parsed.Socks5_pass != nil && parsed.Socks5_user == nil) {
		return nil, fmt.Errorf("both socks5_pass and socks5_user must be specified")
	}
	if (parsed.Socks5_user != nil) && (*parsed.Socks5_user == "") ||
		(parsed.Socks5_pass != nil) && (*parsed.Socks5_pass == "") {
		return nil, fmt.Errorf("socks user or password can't have zero length (https://github.com/golang/go/issues/57285)")
	}
	return &Config{
		Listen_Url:  parsed.Listen_Url,
		Secret:      parsed.Secret,
		Socks5:      parsed.Socks5,
		Socks5_user: parsed.Socks5_user,
		Socks5_pass: parsed.Socks5_pass,
		Users:       userDB,
	}, nil
}
