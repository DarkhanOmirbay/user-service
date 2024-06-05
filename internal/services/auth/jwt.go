package auth

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"sso/internal/domain/models"
	"strings"
	"time"
)

var (
	ErrNotValidJwt = errors.New("not valid jwt")
)

type TokenClaims struct {
	UID   int    `json:"uid"`
	Email string `json:"email"`
	AppID int    `json:"app_id"`
	jwt.MapClaims
}

func NewToken(user models.User, app models.App, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["uid"] = user.ID
	claims["email"] = user.Email
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["app_id"] = app.ID

	tokenString, err := token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func DecodeToken(appSecret string, tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})

	if err != nil {
		switch {
		case strings.Contains(err.Error(), "token is malformed:"):
			return nil, ErrNotValidJwt
		}
		return nil, err
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}
