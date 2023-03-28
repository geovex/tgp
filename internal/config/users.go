package config

type User struct {
	Name   string
	Secret string
	Socks5 *Socks5Data
}

type userDB struct {
	Users map[string]*User
}

func NewUsers() *userDB {
	return &userDB{
		Users: make(map[string]*User),
	}
}

func newOneUser(secret string, socks *Socks5Data) *userDB {
	defuser := User{
		Name:   "_",
		Secret: secret,
		Socks5: socks,
	}
	users := NewUsers()
	users.Users["_"] = &defuser
	return users
}
