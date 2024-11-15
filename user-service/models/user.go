package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Username    string             `bson:"username" json:"username" binding:"required"`
	Password    string             `bson:"password" json:"password" binding:"required"`
	Email       string             `bson:"email" json:"email" binding:"required"`
	Role        string             `bson:"role" json:"role" binding:"required"`
	Permissions []string           `bson:"permissions" json:"permissions"`
	OrgID       string             `bson:"org_id" json:"org_id"`
	CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time          `bson:"updated_at" json:"updated_at"`
}

type Login struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type UpdateUser struct {
	Email       string   `json:"email,omitempty"`
	Password    string   `json:"password,omitempty"`
	Role        string   `json:"role,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

type CreateUserRequest struct {
	Username    string   `json:"username" binding:"required"`
	Password    string   `json:"password" binding:"required"`
	Email       string   `json:"email" binding:"required"`
	Role        string   `json:"role" binding:"required"`
	Permissions []string `json:"permissions"`
}
