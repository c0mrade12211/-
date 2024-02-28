package handlers

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client

func RefreshTokens(c *gin.Context) {
	authorizationHeader := c.GetHeader("Authorization")
	if authorizationHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Отсутствует заголовок авторизации"})
		return
	}

	authHeaderParts := strings.Split(authorizationHeader, " ")
	if len(authHeaderParts) != 2 || authHeaderParts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный формат заголовка авторизации"})
		return
	}

	encodedToken := authHeaderParts[1]
	decodedToken, err := base64.URLEncoding.DecodeString(encodedToken)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Ошибка декодирования токена"})
		return
	}

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(string(decodedToken), claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("memod"), nil
	})
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный токен обновления"})
		return
	}

	expirationTime := time.Unix(int64(claims["exp"].(float64)), 0)
	checkRefresh := time.Now().Before(expirationTime)
	if !checkRefresh {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Токен refresh просрочен"})
		guid, ok := claims["GUID"].(string)
		if ok {
			clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
			client, err := mongo.Connect(context.Background(), clientOptions)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка подключения к базе данных"})
				log.Fatal(err)
				return
			}
			defer client.Disconnect(context.Background())
			collection := client.Database("memods").Collection("tokens")
			_, err = collection.DeleteOne(context.Background(), bson.M{"GUID": guid})
			if err != nil {
				fmt.Println(err)
			}
		}
		return
	}
	guid, ok := claims["GUID"].(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "GUID не найден в токене"})
		return
	}
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка подключения к базе данных"})
		log.Fatal(err)
		return
	}
	defer client.Disconnect(context.Background())

	collection := client.Database("memods").Collection("tokens")
	var result map[string]interface{}
	err = collection.FindOne(context.Background(), bson.M{"GUID": guid}).Decode(&result)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный токен обновления"})
		return
	}

	newAccessToken, err := GenerateAccessToken(guid)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка создания токена доступа"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"GUID": guid, "Access Token": newAccessToken})
}
