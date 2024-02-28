package main

import (
	"tech_task/handlers"

	"github.com/gin-gonic/gin"
)

func main() {
	//Connection to MongoDB in the generateTokens.go - saveTokensToMongoDB() and refreshTokens.go
	router := gin.Default()
	router.GET("/generateTokens/:guid", handlers.GenerateTokens) //guid - string
	router.GET("/refresh", handlers.RefreshTokens)
	router.GET("/auth", handlers.Auth)
	router.Run(":8080")
}
