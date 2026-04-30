package unban

import "time"

type UnbanNamespaceRequest struct {
	Namespace string `uri:"namespace" binding:"required,max=255"`
}

type UnbanIDRequest struct {
	ID uint64 `uri:"id" binding:"required,min=1"`
}

type CreateUnbanRequest struct {
	Namespace    string `json:"namespace" binding:"required,max=255"`
	OperatorName string `json:"operator_name" binding:"required,max=100"`
}

type UnbanResponse struct {
	ID           uint64    `json:"id"`
	Namespace    string    `json:"namespace"`
	OperatorName string    `json:"operator_name"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
