package config

type User struct {
	Name   string
	Secret string
}

type Users struct {
	Users map[string]User
}

func NewUsersSecret(secret string) *Users {
	defuser := User{
		Name:   "_",
		Secret: secret,
	}
	users := map[string]User{
		"_": defuser,
	}
	return &Users{
		Users: users,
	}
}

func NewUsersMap(u map[string]string) (result *Users) {
	result = &Users{
		Users: map[string]User{},
	}
	for k, v := range u {
		result.Users[k] = User{
			Name:   k,
			Secret: v,
		}
	}
	return
}
