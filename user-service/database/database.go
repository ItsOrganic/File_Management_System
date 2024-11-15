package database

import (
	"context"
	"log"
	"time"
	"user-service/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type MongoInstance struct {
	Client *mongo.Client
	DB     *mongo.Database
}

var MI MongoInstance

// Default admin credentials
const (
	DefaultAdminUsername = "admin"
	DefaultAdminPassword = "admin123" // Change this to a secure password
)

// List of all possible permissions
var AllPermissions = []string{
	"create_users",
	"update_users",
	"delete_users",
	"view_users",
	"create_spaces",
	"update_spaces",
	"delete_spaces",
	"view_spaces",
	"upload_files",
	"download_files",
	"delete_files",
	"manage_permissions",
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func ConnectDB() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
	}

	// Ping the database
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}

	MI = MongoInstance{
		Client: client,
		DB:     client.Database("file_management"),
	}

	// Create indexes for unique fields
	createIndexes()

	// Setup default admin user
	setupDefaultAdmin()

	log.Println("Connected to MongoDB!")
}

func createIndexes() {
	// Create unique index for username
	indexModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "username", Value: 1}},
		Options: options.Index().SetUnique(true),
	}

	_, err := MI.DB.Collection("users").Indexes().CreateOne(context.Background(), indexModel)
	if err != nil {
		log.Printf("Error creating index: %v\n", err)
	}
}

func setupDefaultAdmin() {
	// Check if admin user exists
	var existingAdmin models.User
	err := MI.DB.Collection("users").FindOne(
		context.Background(),
		bson.M{"username": DefaultAdminUsername},
	).Decode(&existingAdmin)

	// If admin doesn't exist, create it
	if err == mongo.ErrNoDocuments {
		hashedPassword, err := hashPassword(DefaultAdminPassword)
		if err != nil {
			log.Printf("Error hashing password: %v\n", err)
			return
		}

		adminUser := models.User{
			ID:          primitive.NewObjectID(),
			Username:    DefaultAdminUsername,
			Password:    hashedPassword,
			Email:       "admin@example.com",
			Role:        "admin",
			Permissions: AllPermissions,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		_, err = MI.DB.Collection("users").InsertOne(context.Background(), adminUser)
		if err != nil {
			log.Printf("Error creating admin user: %v\n", err)
			return
		}

		log.Println("Default admin user created successfully")
	} else if err != nil {
		log.Printf("Error checking for admin user: %v\n", err)
	} else {
		log.Println("Admin user already exists")
	}
}
