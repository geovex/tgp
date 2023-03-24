package config

type Users struct {
	Users map[string]string
}

func NewUsersSecret(secret string) *Users {
	users := map[string]string{
		"_": secret,
	}
	return &Users{
		Users: users,
	}
}

func NewUsersMap(u map[string]string) *Users {
	return &Users{Users: u}
}
