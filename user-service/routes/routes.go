package routes

import (
	"user-service/handlers"
	middleware "user-service/middlewares"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine) {
	// Public routes
	r.POST("/login", handlers.LoginHandler)

	// Protected routes
	protected := r.Group("/api")
	protected.Use(middleware.AuthMiddleware())
	{
		protected.POST("/users", handlers.CreateUserHandler)
		protected.PUT("/users/:id", handlers.UpdateUserHandler)
		protected.DELETE("/users/:id", handlers.DeleteUserHandler)
		protected.GET("/users/:id", handlers.GetUserHandler)
	}
}
