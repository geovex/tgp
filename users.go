package main

type Users struct {
	users map[string]string
}

func NewUsersSecret(secret string) *Users {
	users := map[string]string{
		"_": secret,
	}
	return &Users{
		users: users,
	}
}

func NewUsersMap(u map[string]string) *Users {
	return &Users{users: u}
}
