package unban

import (
	"context"

	"gorm.io/gorm"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// CreateUnban creates a new unban record.
func (r *Repository) CreateUnban(ctx context.Context, unban *Unban) error {
	return r.db.WithContext(ctx).Create(unban).Error
}

// GetUnbansByNamespace returns all unban records for the given namespace.
func (r *Repository) GetUnbansByNamespace(ctx context.Context, namespace string) ([]Unban, error) {
	var unbans []Unban
	if err := r.db.WithContext(ctx).Where("namespace = ?", namespace).Order("created_at DESC, id DESC").Find(&unbans).Error; err != nil {
		return nil, err
	}
	if len(unbans) == 0 {
		return nil, gorm.ErrRecordNotFound
	}

	return unbans, nil
}

// ListUnbans returns all unban records.
func (r *Repository) ListUnbans(ctx context.Context) ([]Unban, error) {
	var unbans []Unban
	if err := r.db.WithContext(ctx).Order("created_at DESC, id DESC").Find(&unbans).Error; err != nil {
		return nil, err
	}

	return unbans, nil
}

// DeleteUnbanByID deletes a single unban record by id.
func (r *Repository) DeleteUnbanByID(ctx context.Context, id uint64) error {
	result := r.db.WithContext(ctx).Where("id = ?", id).Delete(&Unban{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}
