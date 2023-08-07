# Simple Telegram proxy #

Inspired by [mtprotoproxy](https://github.com/alexbers/mtprotoproxy)

## Supported features ##
- multiple users (with different secrets)
- socks5 proxy
- Fake tls protocol
- stats through unix socket
## Experimental features
- adtag support (direct egress connection is required,
                 no nat or proxy, ip can not be hidden)

## Not supported (yet) ##
- media CDN support

## Starting ##

`./tgp <config_path.toml>`

# Config #

Config file is a toml-formatted file. For example:

## Minimal config ##

```toml
listen_url = "0.0.0.0:6666"
secret = "dd000102030405060708090a0b0c0d0e0f"
```

## Config file format ##
```toml
listen_url = ["0.0.0.0:6666", "[::]:6666"]
# listen_url = "0.0.0.0:6666" #you can specify one listen address
ipv6 = true # try IPv6 while connecting to DC
# ignore wrong timestamp for clients during faketls auth
#ignore_timestamp = false
# path for unix domain socket for getting stats
# you can get results with socat
stats_sock = "tgp.stats"
# optional obfuscation for outgoing connections
obfuscate = true
# fallback host for dpi connection probes (optional)
host = "google.com:443"
# Global secret can be specified here. And just one user "_" will be configured.
# (optional)
#secret = "dd000102030405060708090a0b0c0d0e0f"
# Set socks5 proxy for egress traffic (optional, disables middleproxy)
socks5 = "127.0.0.1:9050"
# Auth for SOCKS5 (optional)
socks5_user = "test"
socks5_pass = "test"
[users]
1 = "dd000102030405060708090a0b0c0d0e0f"
[users.2] 
secret = "dd101112131415161718191a1b1c1d1e1f"
socks5_user = "2" # specify auth for user
socks5_pass = "2"
[users.3]
obfuscate = false
secret = "dd303132333435363738393a3b3c3d3e3f"
socks5 = "" # override user 3 to direct conneection
[users.4]
secret = "dd404142434445464748494a4b4c4d4e4f"
socks5 = "127.0.0.2:9050" # override to different proxy
socks5_user = "4" 
socks5_pass = "4"
[users.5]
secret = "dd505152535455565758595a5b5c5d5e5f"
socks5 = "" # direct connection requires for adtag
adtag = "0000000000000000000000000000000001"
```

Multiple user support is done via matching the handshake packet to the secret of
each user. Therefore, the login process will consume more CPU time the more
users you set up. Additionally, checks are fairly simple, and collisions are
possible.