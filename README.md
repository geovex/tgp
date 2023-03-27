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
# Optional auth
# Now empty password is not allowed. because of https://github.com/golang/go/issues/57285
socks5_user = "test"
socks5_pass = "test"
[users]
1 = "dd000102030405060708090a0b0c0d0e0f"
[users.2] 
secret = "dd101112131415161718191a1b1c1d1e1f"
socks5_user = "2" # specify auth for user
socks5_pass = "2"
[3]
secret = "dd303132333435363738393a3b3c3d3e3f"
socks5 = "" # override user 3 to direct conneection
[4]
secret = "dd404142434445464748494a4b4c4d4e4f"
socks5 = "127.0.0.2:9050" # override to different proxy
socks5_user = "4" 
socks5_pass = "4"
```

Multiple users support achieved by checking handshake packet against each 
user's secret. So the more users you set the more cpu time login procedure
will use. Also checks are very basic and there are some probability of
collisions.
