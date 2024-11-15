package main

import (
	"user-service/database"
	"user-service/routes"

	"github.com/gin-gonic/gin"
)

func main() {
	// Connect to MongoDB
	database.ConnectDB()

	// Create Gin router
	r := gin.Default()

	// Setup routes
	routes.SetupRoutes(r)

	// Start server
	r.Run(":8080")
}
