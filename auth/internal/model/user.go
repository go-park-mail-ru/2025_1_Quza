package model

import (
	"github.com/dgrijalva/jwt-go"
)

type (
	User struct {
		ID       int    `db:"id" redis:"id" json:"id"`
		Name     string `db:"name" json:"name"`
		Email    string `db:"email" json:"email"`
		Password string `db:"password" json:"password"`
		Role     string `db:"role" json:"role"`
	}

	UserPayload struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}

	UserClaims struct {
		jwt.StandardClaims
		Username string `json:"username"`
		Role     string `json:"role"`
	}
)
