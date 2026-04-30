package ban

import (
	"context"
	"time"

	"gorm.io/gorm"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// CreateBan creates a new ban record.
func (r *Repository) CreateBan(ctx context.Context, ban *Ban) error {
	return r.db.WithContext(ctx).Create(ban).Error
}

// GetBansByNamespace returns all ban records for the given namespace.
func (r *Repository) GetBansByNamespace(ctx context.Context, namespace string) ([]Ban, error) {
	var bans []Ban
	if err := r.db.WithContext(ctx).Where("namespace = ?", namespace).Order("ban_start_time DESC, id DESC").Find(&bans).Error; err != nil {
		return nil, err
	}
	if len(bans) == 0 {
		return nil, gorm.ErrRecordNotFound
	}

	return bans, nil
}

// ListBans returns all ban records.
func (r *Repository) ListBans(ctx context.Context) ([]Ban, error) {
	var bans []Ban
	if err := r.db.WithContext(ctx).Order("ban_start_time DESC, id DESC").Find(&bans).Error; err != nil {
		return nil, err
	}

	return bans, nil
}

// DeleteBanByID deletes a single ban record by id.
func (r *Repository) DeleteBanByID(ctx context.Context, id uint64) error {
	result := r.db.WithContext(ctx).Where("id = ?", id).Delete(&Ban{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

// HasActiveBan reports whether the given namespace currently has any active ban records.
func (r *Repository) HasActiveBan(ctx context.Context, namespace string, now time.Time) (bool, error) {
	var count int64
	if err := r.db.WithContext(ctx).
		Model(&Ban{}).
		Where("namespace = ?", namespace).
		Where("ban_start_time <= ?", now).
		Where("ban_end_time IS NULL OR ban_end_time >= ?", now).
		Count(&count).Error; err != nil {
		return false, err
	}

	return count > 0, nil
}
