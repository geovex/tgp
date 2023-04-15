package config

import (
	"encoding/hex"
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/geovex/tgp/internal/tgcrypt"
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
	c, err := configFromParsedUnchecked(parsed, md)
	if err != nil {
		return nil, err
	}
	for u := range c.IterateUsers() {
		userData, _ := c.GetUser(u.Name)
		err = checkUser(&userData)
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func configFromParsedUnchecked(parsed *parsedConfig, md *toml.MetaData) (*Config, error) {
	//parse listen url
	var listenUrls []string
	if md.Type("listen_url") == "String" {
		var url string
		err := md.PrimitiveDecode(parsed.Listen_Url, &url)
		if err != nil {
			return nil, err
		}
		listenUrls = []string{url}
	} else if md.Type("listen_url") == "Array" {
		err := md.PrimitiveDecode(parsed.Listen_Url, &listenUrls)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("listen_url must be string or array")
	}
	//check for ipv6
	var allowIPv6 bool
	if parsed.AllowIPv6 == nil {
		allowIPv6 = false
	} else {
		allowIPv6 = *parsed.AllowIPv6
	}
	var obfuscate bool
	if parsed.Obfuscate == nil {
		obfuscate = false
	} else {
		obfuscate = *parsed.Obfuscate
	}
	var users *userDB
	if parsed.Users != nil && parsed.Secret == nil {
		users = NewUsers()
		for name, data := range *parsed.Users {
			var u User
			// user defined by it's secret
			utype := md.Type("users", name)
			if utype == "String" {
				var secret string
				err := md.PrimitiveDecode(data, &secret)
				if err != nil {
					return nil, err
				}
				u = User{
					Name:        name,
					Secret:      secret,
					Obfuscate:   parsed.Obfuscate,
					AdTag:       parsed.Adtag,
					Socks5:      parsed.Socks5,
					Socks5_user: parsed.Socks5_user,
					Socks5_pass: parsed.Socks5_pass,
				}
			} else if utype == "Hash" { // user fully defined
				var pu parsedUserPrimitive
				err := md.PrimitiveDecode(data, &pu)
				if err != nil {
					return nil, err
				}
				if err != nil {
					return nil, err
				}
				u = User{
					Name:        name,
					Secret:      pu.Secret,
					AdTag:       pu.Adtag,
					Obfuscate:   pu.Obfuscate,
					Socks5:      pu.Socks5,
					Socks5_user: pu.Socks5_user,
					Socks5_pass: pu.Socks5_pass,
				}
			} else {
				return nil, fmt.Errorf("unknown type for user %s: %s ", name, utype)
			}
			users.Users[name] = &u
		}
	} else if parsed.Users == nil && parsed.Secret != nil {
		users = newOneUser(*parsed.Secret, parsed.Socks5, parsed.Socks5_user, parsed.Socks5_pass)
	} else {
		return nil, fmt.Errorf("specify either secret or users")
	}
	return &Config{
		listen_Urls: listenUrls,
		allowIPv6:   allowIPv6,
		obfuscate:   obfuscate,
		AdTag:       parsed.Adtag,
		secret:      parsed.Secret,
		host:        parsed.Host,
		socks5:      parsed.Socks5,
		socks5_user: parsed.Socks5_user,
		socks5_pass: parsed.Socks5_pass,
		users:       users,
	}, nil
}

func checkUser(user *User) error {
	// socks6 checks
	if user.Socks5 != nil {
		if (user.Socks5_user != nil) != (user.Socks5_pass != nil) {
			return fmt.Errorf("both socks5 and socks5_pass must be specified")
		} else if user.Socks5_user != nil && (*user.Socks5_user == "") && (*user.Socks5_pass == "") {
			return fmt.Errorf("socks5 user or password can't have zero length (https://github.com/golang/go/issues/57285)")
		}
		if user.AdTag != nil {
			if user.Socks5 != nil {
				return fmt.Errorf("middle proxy requires direct connection")
			} else {
				adTag, err := hex.DecodeString(*user.AdTag)
				if err != nil {
					return fmt.Errorf("can't parse adtag: %w", err)
				}
				if len(adTag) != tgcrypt.AddTagLength {
					return fmt.Errorf("adtag must be %d bytes", tgcrypt.AddTagLength)
				}
			}
		}

	}
	return nil
}
