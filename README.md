# Simple Telegram proxy #

Inspired by [mtprotoproxy](https://github.com/alexbers/mtprotoproxy)

## Supported features ##
- multiple users (with different secrets)
- socks5 proxy
- Fake tls protocol

## Not supported (yet) ##

- middleproxy protocol
- IPv6
- fallback fake tls to original host
- socks5 auth
- AD_TAG (requires middleproxy)

## Starting ##

`./tgp <config_path.toml>`

# Config file format
Config file is a toml-formatted file. For example:
```toml
listen_url = "0.0.0.0:6666"
# You can specify global secret for user _ here
#secret = "dd000102030405060708090a0b0c0d0e0f"
# Set socks5 proxy in case you need to use one
socks5 = "127.0.0.1:9050"

# Or define multiple users here
[users]
1 = "dd000102030405060708090a0b0c0d0e0f"
2 = "dd101112131415161718191a1b1c1d1e1f"
```

Multiple users support achieved by checking handshake packet against each 
user's secret. So the more users you set the more cpu time login procedure
will use. Also checks are very basic and there are some probability of
collisions.