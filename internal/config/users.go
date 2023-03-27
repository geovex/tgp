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

func newUsersSecret(secret string, socks *Socks5Data) *userDB {
	defuser := User{
		Name:   "_",
		Secret: secret,
		Socks5: socks,
	}
	users := NewUsers()
	users.Users["_"] = &defuser
	return users
}

func newUsersMap(u map[string]string) (result *userDB) {
	result = &userDB{
		Users: map[string]*User{},
	}
	for k, v := range u {
		result.Users[k] = &User{
			Name:   k,
			Secret: v,
		}
	}
	return
}
