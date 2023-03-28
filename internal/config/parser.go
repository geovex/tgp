package config

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

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
	var users *userDB
	if parsed.Users != nil && parsed.Secret == nil {
		users = NewUsers()
		for name, data := range *parsed.Users {
			// user defined by it's secret
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
			} else if utype == "Hash" { // user fully defined
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
		users = newOneUser(*parsed.Secret, defsocks)
	} else {
		return nil, fmt.Errorf("specify either secret or users")
	}
	return &Config{
		listen_Url: parsed.Listen_Url,
		secret:     parsed.Secret,
		host:       parsed.Host,
		defsocks:   defsocks,
		users:      users,
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
