package config

type User struct {
	Name   string
	Secret string
	Socks5 *Socks5Data
}

type Users struct {
	Users map[string]*User
}

func NewUsers() *Users {
	return &Users{
		Users: make(map[string]*User),
	}
}

func NewUsersSecret(secret string, socks Socks5Data) *Users {
	defuser := User{
		Name:   "_",
		Secret: secret,
	}
	users := NewUsers()
	users.Users["_"] = &defuser
	return users
}

func NewUsersMap(u map[string]string) (result *Users) {
	result = &Users{
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
