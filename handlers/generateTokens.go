package handlers

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func GenerateTokens(c *gin.Context) {
	GUID := c.Param("guid")
	if GUID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "[-] GUID required"})
		return
	}
	accessToken, err := GenerateAccessToken(GUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "[-] Error creating access Token"})
		return
	}
	refreshToken, err := generateRefreshToken(GUID)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "[-] Error creating refresh Token"})
		return
	}
	err = saveTokensToMongoDB(GUID, refreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "[-] Error saving values to MongoDB"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"Access Token": accessToken, "Refresh Token": refreshToken})
}
func generateRefreshToken(guid string) (string, error) {
	refreshClaims := jwt.MapClaims{
		"exp":  time.Now().Add(time.Hour * 24).Unix(),
		"GUID": guid,
	}
	refreshTokenJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	tokenString, err := refreshTokenJWT.SignedString([]byte("memod"))
	if err != nil {
		return "", err
	}
	encodedToken := base64.URLEncoding.EncodeToString([]byte(tokenString))
	return encodedToken, nil
}

func GenerateAccessToken(GUID string) (string, error) {
	accessClaims := jwt.MapClaims{
		"GUID": GUID,
		"exp":  time.Now().Add(time.Hour).Unix(),
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte("memod"))
	if err != nil {
		return "", err
	}
	return accessTokenString, nil
}

func saveTokensToMongoDB(GUID, refreshToken string) error {
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		return err
	}
	defer client.Disconnect(context.Background())
	collection := client.Database("memods").Collection("tokens")
	document := bson.M{"GUID": GUID, "RefreshToken": refreshToken}
	_, err = collection.InsertOne(context.Background(), document)
	if err != nil {
		return err
	}
	return nil
}
