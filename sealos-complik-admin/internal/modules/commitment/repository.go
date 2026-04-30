package commitment

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

// CreateCommitment creates a new commitment record.
func (r *Repository) CreateCommitment(ctx context.Context, commitment *Commitment) error {
	return r.db.WithContext(ctx).Create(commitment).Error
}

// GetCommitmentByNamespace returns a commitment by namespace.
func (r *Repository) GetCommitmentByNamespace(ctx context.Context, namespace string) (*Commitment, error) {
	var commitment Commitment
	if err := r.db.WithContext(ctx).Where("namespace = ?", namespace).First(&commitment).Error; err != nil {
		return nil, err
	}

	return &commitment, nil
}

// ListCommitments returns all commitment records.
func (r *Repository) ListCommitments(ctx context.Context) ([]Commitment, error) {
	var commitments []Commitment
	if err := r.db.WithContext(ctx).Order("id ASC").Find(&commitments).Error; err != nil {
		return nil, err
	}

	return commitments, nil
}

// UpdateCommitment updates an existing commitment record.
func (r *Repository) UpdateCommitment(ctx context.Context, commitment *Commitment) error {
	return r.db.WithContext(ctx).Save(commitment).Error
}

// DeleteCommitmentByNamespace deletes commitment records for the given namespace.
func (r *Repository) DeleteCommitmentByNamespace(ctx context.Context, namespace string) error {
	result := r.db.WithContext(ctx).Where("namespace = ?", namespace).Delete(&Commitment{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}
