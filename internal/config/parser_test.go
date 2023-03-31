package config

import (
	"testing"

	"github.com/BurntSushi/toml"
)

func TestDefaultConfig(t *testing.T) {
	var config = defaultConfigData
	var pc parsedConfig
	md, err := toml.Decode(config, &pc)
	if err != nil {
		t.Errorf("default config not decoded: %v", err)
	}
	_, err = configFromParsed(&pc, &md)
	if err != nil {
		t.Errorf("default config not parsed: %v", err)
	}
}

func TestSimpleConfig(t *testing.T) {
	var pc parsedConfig
	var config = `
		listen_url = "0.0.0.0:6666"
		secret = "dd000102030405060708090a0b0c0d0e0f"
	`
	md, err := toml.Decode(config, &pc)
	if err != nil {
		t.Errorf("simple config not decoded: %v", err)
	}
	c, err := configFromParsed(&pc, &md)
	if err != nil {
		t.Errorf("simple config not parsed: %v", err)
	}
	_, err = c.GetUser("_")
	if err != nil {
		t.Errorf("no default user in simple config")
	}
}

func TestProxyInheritance(t *testing.T) {
	config := `
		listen_url = "0.0.0.0:6666"
		socks5 = "127.0.0.1:9050"
		[users.inherit]
		secret = "dd000102030405060708090a0b0c0d0e0f"
		[users.direct]
		secret = "dd101112131415161718191a1b1c1d1e1f"
		socks5 = ""
		[users.another_proxy]
		secret = "dd202122232425262728292a2b2c2d2e2f"
		socks5 = "192.168.1.1:9050"
	`
	var pc parsedConfig
	md, err := toml.Decode(config, &pc)
	if err != nil {
		t.Errorf("proxy inheritance config not decoded: %v", err)
	}
	c, err := configFromParsed(&pc, &md)
	if err != nil {
		t.Errorf("proxy inheritance config not parsed: %v", err)
	}
	inherit, err := c.GetSocks5("inherit")
	if err != nil {
		t.Errorf("no inherit user in proxy inheritance config")
	}
	if inherit.Url != "127.0.0.1:9050" {
		t.Errorf("inherit user socks not 127.0.0.1:9050")
	}
	direct, err := c.GetSocks5("direct")
	if err != nil {
		t.Errorf("no direct user in proxy inheritance config")
	}
	if direct != nil {
		t.Errorf("direct user is not directly connected")
	}
	another_proxy, err := c.GetSocks5("another_proxy")
	if err != nil {
		t.Errorf("no another_proxy user in proxy inheritance config")
	}
	if another_proxy.Url != "192.168.1.1:9050" {
		t.Errorf("another_proxy user socks not 192.168.1.1:9050")
	}
}

func TestMultipleListenUrls(t *testing.T) {
	config := `
		listen_url = ["0.0.0.0:6666", "[::]:443"]
		secret = "dd000102030405060708090a0b0c0d0e0f"
	`
	var pc parsedConfig
	md, err := toml.Decode(config, &pc)
	if err != nil {
		t.Errorf("multiple listen_url config not decoded: %v", err)
	}
	c, err := configFromParsed(&pc, &md)
	if err != nil {
		t.Errorf("multiple listen_url config not parsed: %v", err)
	}
	if c.GetListenUrl()[0] != "0.0.0.0:6666" || c.GetListenUrl()[1] != "[::]:443" {
		t.Errorf("multiple listen_url not parsed correctly")
	}
}
