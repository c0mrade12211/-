package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func Auth(c *gin.Context) {
	authorizationHeader := c.GetHeader("Authorization")
	if authorizationHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Отсутствует хедер"})
		return
	}
	authHeaderParts := strings.Split(authorizationHeader, " ")
	if len(authHeaderParts) != 2 || authHeaderParts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный формат хедера авторизации"})
		return
	}
	accessToken := authHeaderParts[1]

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("memod"), nil
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "[-] Ошибка при разборе access tokena"})
		return
	}
	expirationTime := time.Unix(int64(claims["exp"].(float64)), 0)
	checkAccess := time.Now().Before(expirationTime)
	if !checkAccess {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "[-] Срок действия access token истек идите в refresh"})
	}
	c.JSON(http.StatusOK, gin.H{"response": "OK"})
}
