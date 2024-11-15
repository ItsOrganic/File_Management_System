package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"
	"user-service/database"
	"user-service/models"
	"user-service/utils"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

// Add this password hashing function at the top
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// Add this password verification function
func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func LoginHandler(c *gin.Context) {
	var loginRequest models.Login
	if err := c.BindJSON(&loginRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	var user models.User
	filter := bson.M{"username": loginRequest.Username}
	err := database.MI.DB.Collection("users").FindOne(context.Background(), filter).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Use the checkPassword function
	if !checkPassword(loginRequest.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, err := utils.GenerateJWT(user.Username, user.Role, user.Permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user": gin.H{
			"id":          user.ID,
			"username":    user.Username,
			"email":       user.Email,
			"role":        user.Role,
			"permissions": user.Permissions,
		},
	})
}

func CreateUserHandler(c *gin.Context) {
	// Add debug logging
	fmt.Println("Starting CreateUserHandler")

	// Get creator's role and permissions from the JWT token
	creatorRole, exists := c.Get("role")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized - no role found"})
		return
	}

	creatorPermissions, exists := c.Get("permissions")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized - no permissions found"})
		return
	}

	// Type assertion for permissions
	permissions, ok := creatorPermissions.([]string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid permissions format"})
		return
	}

	if !utils.HasPermission(permissions, "create_users") {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	// Use the CreateUserRequest struct for binding
	var createRequest models.CreateUserRequest
	if err := c.BindJSON(&createRequest); err != nil {
		fmt.Printf("BindJSON error: %v\n", err) // Debug log
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request format"})
		return
	}

	// Debug print the received data
	fmt.Printf("Received user data: %+v\n", createRequest)

	// Check if trying to create admin user
	if createRequest.Role == "admin" && creatorRole.(string) != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "only admins can create admin users"})
		return
	}

	// Check if username already exists
	var existingUser models.User
	err := database.MI.DB.Collection("users").FindOne(
		context.Background(),
		bson.M{"username": createRequest.Username},
	).Decode(&existingUser)

	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "username already exists"})
		return
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(createRequest.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "password processing failed"})
		return
	}

	// Create new user from request
	newUser := models.User{
		ID:          primitive.NewObjectID(),
		Username:    createRequest.Username,
		Password:    hashedPassword,
		Email:       createRequest.Email,
		Role:        createRequest.Role,
		Permissions: createRequest.Permissions,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Insert user
	_, err = database.MI.DB.Collection("users").InsertOne(context.Background(), newUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user creation failed"})
		return
	}

	// Clear password before sending response
	newUser.Password = ""
	c.JSON(http.StatusCreated, newUser)
}

func UpdateUserHandler(c *gin.Context) {
	userID := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	currentRole, _ := c.Get("role")
	currentPermissions, _ := c.Get("permissions")
	permissions := currentPermissions.([]string)

	if !utils.HasPermission(permissions, "update_users") {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	var updateData models.UpdateUser
	if err := c.BindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	var existingUser models.User
	err = database.MI.DB.Collection("users").FindOne(context.Background(), bson.M{"_id": objID}).Decode(&existingUser)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	if updateData.Role == "admin" && currentRole != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "only admins can assign admin role"})
		return
	}

	update := bson.M{"$set": bson.M{"updated_at": time.Now()}}
	if updateData.Email != "" {
		update["$set"].(bson.M)["email"] = updateData.Email
	}
	if updateData.Password != "" {
		// Hash the new password before updating
		hashedPassword, err := hashPassword(updateData.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "password processing failed"})
			return
		}
		update["$set"].(bson.M)["password"] = hashedPassword
	}
	if updateData.Role != "" {
		update["$set"].(bson.M)["role"] = updateData.Role
	}
	if updateData.Permissions != nil {
		update["$set"].(bson.M)["permissions"] = updateData.Permissions
	}

	result, err := database.MI.DB.Collection("users").UpdateOne(
		context.Background(),
		bson.M{"_id": objID},
		update,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}

	if result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user updated successfully"})
}

func DeleteUserHandler(c *gin.Context) {
	permissions, _ := c.Get("permissions")
	if !utils.HasPermission(permissions.([]string), "delete_users") {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	userID := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	result, err := database.MI.DB.Collection("users").DeleteOne(context.Background(), bson.M{"_id": objID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "deletion failed"})
		return
	}

	if result.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user deleted successfully"})
}

func GetUserHandler(c *gin.Context) {
	permissions, _ := c.Get("permissions")
	if !utils.HasPermission(permissions.([]string), "view_users") {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	userID := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	var user models.User
	err = database.MI.DB.Collection("users").FindOne(context.Background(), bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Clear password before sending response
	user.Password = ""
	c.JSON(http.StatusOK, user)
}
