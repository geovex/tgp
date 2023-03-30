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

// TODO: need some tests
func (p *parsedUserPrimitive) getSocks(parent *Socks5Data) (s *Socks5Data, err error) {
	if p.Socks5 == nil && p.Socks5_user == nil {
		return parent, nil
	} else if p.Socks5 == nil && p.Socks5_user != nil {
		err = checkSocksValues(p.Socks5_user, p.Socks5_pass)
		if err != nil {
			return nil, err
		}
		s = &Socks5Data{
			Url:  parent.Url,
			User: p.Socks5_user,
			Pass: p.Socks5_pass}
		return s, nil
	} else if *p.Socks5 == "" {
		return nil, nil
	} else {
		err = checkSocksValues(p.Socks5_user, p.Socks5_pass)
		if err != nil {
			return nil, err
		}
		s = &Socks5Data{
			Url:  *p.Socks5,
			User: p.Socks5_user,
			Pass: p.Socks5_pass,
		}
		return s, nil
	}
}

type Config struct {
	listen_Urls []string
	allowIPv6   bool
	secret      *string
	host        *string
	defsocks    *Socks5Data
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

func (c *Config) GetDefaultSocks() *Socks5Data {
	return c.defsocks
}

func (c *Config) GetSocks5(user string) (*Socks5Data, error) {
	u, err := c.GetUser(user)
	if err != nil {
		return nil, err
	}
	return u.Socks5, nil
}
func (c *Config) GetHost() *string {
	return c.host
}
