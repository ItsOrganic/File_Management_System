package utils

import (
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("your-secret-key") // In production, use environment variable

func GenerateJWT(username string, role string, permissions []string) (string, error) {
	claims := jwt.MapClaims{
		"username":    username,
		"role":        role,
		"permissions": permissions,
		"exp":         time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func HasPermission(permissions []string, requiredPermission string) bool {
	for _, p := range permissions {
		if p == requiredPermission {
			return true
		}
	}
	return false
}
