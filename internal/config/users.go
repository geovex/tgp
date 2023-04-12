package config

type User struct {
	Name        string
	Secret      string
	Obfuscate   *bool
	Middleproxy *bool
	Socks5      *string
	Socks5_user *string
	Socks5_pass *string
}

type userDB struct {
	Users map[string]*User
}

func NewUsers() *userDB {
	return &userDB{
		Users: make(map[string]*User),
	}
}

func newOneUser(secret string, socks5 *string, user *string, pass *string) *userDB {
	defuser := User{
		Name:        "_",
		Secret:      secret,
		Socks5:      socks5,
		Socks5_user: user,
		Socks5_pass: pass,
	}
	users := NewUsers()
	users.Users["_"] = &defuser
	return users
}
