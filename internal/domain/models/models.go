package models

type User struct {
	ID           int64
	Fname        string
	Lname        string
	Email        string
	Role         string
	Activated    bool
	PasswordHash Password
}
type UserProto struct {
	Fname    string
	Lname    string
	Email    string
	Password string
}

type Password struct {
	PlainText *string
	Hash      []byte
}

type App struct {
	ID     int
	Name   string
	Secret string
}
