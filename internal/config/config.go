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
host = "google.com:443"
socks5_user = "test"
socks5_pass = "test"
#obfuscate = true
allowipv6 = true
[users]
1 = "dd000102030405060708090a0b0c0d0e0f"
[users.2] 
secret = "dd101112131415161718191a1b1c1d1e1f"
socks5 = ""
adtag = "0000000000000000000000000000000000"
`

type parsedConfig struct {
	Listen_Url  toml.Primitive
	Secret      *string
	Host        *string
	Stats_Sock  *string
	Obfuscate   *bool
	Adtag       *string
	Socks5      *string
	Socks5_user *string
	Socks5_pass *string
	AllowIPv6   *bool
	Users       *map[string]toml.Primitive
}

type parsedUserPrimitive struct {
	Secret      string
	Obfuscate   *bool
	Adtag       *string
	Socks5      *string
	Socks5_user *string
	Socks5_pass *string
}

type Config struct {
	listen_Urls []string
	allowIPv6   bool
	secret      *string
	host        *string
	stats_sock  *string
	obfuscate   bool
	AdTag       *string
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

func (c *Config) GetUser(user string) (u User, err error) {
	// TODO: may be add user cache
	userData, ok := c.users.Users[user]
	if !ok {
		return u, fmt.Errorf("user %s not found", user)
	}
	// process property inheritance
	u = *userData
	if u.Obfuscate == nil {
		u.Obfuscate = &c.obfuscate
	}
	if u.AdTag == nil {
		u.AdTag = c.AdTag
	}
	if u.Socks5 == nil {
		u.Socks5 = c.socks5
	} else if *u.Socks5 == "" {
		u.Socks5 = nil
	}
	if u.Socks5_user == nil {
		u.Socks5_user = c.socks5_user
	}
	if u.Socks5_pass == nil {
		u.Socks5_pass = c.socks5_pass
	}
	return
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

func (c *Config) IterateUsers() chan *User {
	result := make(chan *User)
	go func() {
		defer close(result)
		for _, u := range c.users.Users {
			result <- u
		}
	}()
	return result
}

func (c *Config) GetDefaultSocks() (url, user, pass *string) {
	return c.socks5, c.socks5_user, c.socks5_pass
}

func (c *Config) GetHost() *string {
	return c.host
}

func (c *Config) GetStatsSock() *string {
	return c.stats_sock
}
