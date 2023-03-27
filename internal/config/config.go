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
[users.2] 
secret = "dd101112131415161718191a1b1c1d1e1f"
`

type parsedConfig struct {
	Listen_Url  string
	Secret      *string
	Socks5      *string
	Socks5_user *string
	Socks5_pass *string
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
	Listen_Url string
	Secret     *string
	Users      *Users
}

func ReadConfig(path string) (*Config, error) {
	var c parsedConfig
	md, err := toml.DecodeFile(path, &c)
	if err != nil {
		return nil, err
	}
	result, err := configFromParsed(&c, &md)
	if err != nil {
		return result, err
	}
	return result, nil
}

func DefaultConfig() *Config {
	var c parsedConfig
	md, err := toml.Decode(defaultConfigData, &c)
	if err != nil {
		panic(err)
	}
	result, err := configFromParsed(&c, &md)
	if err != nil {
		panic(err)
	}
	return result
}
func configFromParsed(parsed *parsedConfig, md *toml.MetaData) (*Config, error) {
	//check for common defsocks
	var defsocks *Socks5Data
	if parsed.Socks5 != nil {
		err := checkSocksValues(parsed.Socks5_user, parsed.Socks5_pass)
		if err != nil {
			return nil, err
		}
		defsocks = &Socks5Data{
			Url:  *parsed.Socks5,
			User: parsed.Socks5_user,
			Pass: parsed.Socks5_pass,
		}
	}
	var users *Users
	if parsed.Users != nil && parsed.Secret == nil {
		users = NewUsers()
		for name, data := range *parsed.Users {
			utype := md.Type("users", name)
			if utype == "String" {
				var secret string
				err := md.PrimitiveDecode(data, &secret)
				if err != nil {
					return nil, err
				}
				users.Users[name] = &User{
					Name:   name,
					Secret: secret,
					Socks5: defsocks,
				}
			} else if utype == "Hash" {
				var pu parsedUserPrimitive
				err := md.PrimitiveDecode(data, &pu)
				if err != nil {
					return nil, err
				}
				usersocks, err := pu.getSocks(defsocks)
				if err != nil {
					return nil, err
				}
				users.Users[name] = &User{
					Name:   name,
					Secret: pu.Secret,
					Socks5: usersocks,
				}
			} else {
				return nil, fmt.Errorf("unknown type for user %s: %s ", name, utype)
			}
		}
	} else if parsed.Users == nil && parsed.Secret != nil {
		users = NewUsersSecret(*parsed.Secret, defsocks)
	} else {
		return nil, fmt.Errorf("specify either secret or users")
	}
	err := checkSocksValues(parsed.Socks5_user, parsed.Socks5_user)
	if err != nil {
		return nil, err
	}
	return &Config{
		Listen_Url: parsed.Listen_Url,
		Secret:     parsed.Secret,
		Users:      users,
	}, nil
}

func checkSocksValues(user *string, pass *string) error {
	if (user == nil && pass != nil) ||
		(user != nil && pass == nil) {
		return fmt.Errorf("both socks5_pass and socks5_user must be specified")
	}
	if (user != nil) && (*user == "") ||
		(pass != nil) && (*pass == "") {
		return fmt.Errorf("socks user or password can't have zero length (https://github.com/golang/go/issues/57285)")
	}
	return nil
}
