package config

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

var defaultConfigData = `
listen_url = "0.0.0.0:6666"
#secret = "dd000102030405060708090a0b0c0d0e0f"
socks5 = "127.0.0.1:9050"
ipv6 = true
# For now empty password is not allowed. because of https://github.com/golang/go/issues/57285
host = "google.com:443"
socks5_user = "test"
socks5_pass = "test"
[users]
1 = "dd000102030405060708090a0b0c0d0e0f"
[users.2] 
secret = "dd101112131415161718191a1b1c1d1e1f"
`

type parsedConfig struct {
	Listen_Url  toml.Primitive
	Secret      *string
	Host        *string
	Socks5      *string
	Socks5_user *string
	Socks5_pass *string
	AllowIPv6   *bool
	Users       *map[string]toml.Primitive
}

type parsedUserPrimitive struct {
	Secret      string
	Socks5      *string
	Socks5_user *string
	Socks5_pass *string
}

type Config struct {
	listen_Urls []string
	allowIPv6   bool
	secret      *string
	host        *string
	socks5      *string
	socks5_user *string
	socks5_pass *string
	users       *userDB
}

func (c *Config) GetListenUrl() []string {
	return c.listen_Urls
}

func (c *Config) GetAllowIPv6() bool {
	return c.allowIPv6
}

func (c *Config) GetUser(user string) (*User, error) {
	userData, ok := c.users.Users[user]
	if !ok {
		return nil, fmt.Errorf("user %s not found", user)
	} else {
		return userData, nil
	}
}

func (c *Config) GetUserSecret(user string) (string, error) {
	if c.secret == nil {
		userData, err := c.GetUser(user)
		if err != nil {
			return "", err
		}
		return userData.Secret, nil
	} else {
		return *c.secret, nil
	}
}

func (c *Config) IterateUsers(f func(user, secret string) (stop bool)) {
	for k, v := range c.users.Users {
		if f(k, v.Secret) {
			return
		}
	}
}

func (c *Config) GetDefaultSocks() (url, user, pass *string) {
	return c.socks5, c.socks5_user, c.socks5_pass
}

func (c *Config) GetSocks5(userName string) (url, user, pass *string, err error) {
	u, err := c.GetUser(userName)
	if err != nil {
		return
	}
	url = u.Socks5
	if url == nil {
		url = c.socks5
	} else if *url == "" {
		url = nil
	}
	user = u.Socks5_user
	if user == nil {
		user = c.socks5_user
	}
	pass = u.Socks5_pass
	if pass == nil {
		pass = c.socks5_pass
	}
	return
}
func (c *Config) GetHost() *string {
	return c.host
}
