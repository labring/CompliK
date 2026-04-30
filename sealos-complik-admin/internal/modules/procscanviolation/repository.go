package procscanviolation

import (
	"context"

	"gorm.io/gorm"
)

type Repository struct {
	db *gorm.DB
}

const procscanEffectiveViolationCondition = `
(
	JSON_UNQUOTE(JSON_EXTRACT(raw_payload, '$."进程信息"."是否违规"')) = 'true'
	OR JSON_UNQUOTE(JSON_EXTRACT(raw_payload, '$.process_info.IsIllegal')) = 'true'
	OR JSON_UNQUOTE(JSON_EXTRACT(raw_payload, '$.process_info.is_illegal')) = 'true'
	OR JSON_UNQUOTE(JSON_EXTRACT(raw_payload, '$.is_illegal')) = 'true'
	OR JSON_UNQUOTE(JSON_EXTRACT(raw_payload, '$.IsIllegal')) = 'true'
	OR (
		JSON_EXTRACT(raw_payload, '$."进程信息"."是否违规"') IS NULL
		AND JSON_EXTRACT(raw_payload, '$.process_info.IsIllegal') IS NULL
		AND JSON_EXTRACT(raw_payload, '$.process_info.is_illegal') IS NULL
		AND JSON_EXTRACT(raw_payload, '$.is_illegal') IS NULL
		AND JSON_EXTRACT(raw_payload, '$.IsIllegal') IS NULL
		AND is_illegal = TRUE
	)
)
`

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) CreateViolation(ctx context.Context, violation *ProcscanViolationEvent) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(violation).Error; err != nil {
			return err
		}
		if !violation.IsIllegal {
			return tx.Model(&ProcscanViolationEvent{}).
				Where("id = ?", violation.ID).
				Update("is_illegal", false).Error
		}

		return nil
	})
}

func (r *Repository) GetViolationsByNamespace(ctx context.Context, namespace string, includeAll bool) ([]ProcscanViolationEvent, error) {
	var violations []ProcscanViolationEvent
	query := r.db.WithContext(ctx).Where("namespace = ?", namespace)
	if !includeAll {
		query = query.Where(procscanEffectiveViolationCondition)
	}

	if err := query.
		Order("detected_at DESC, id DESC").
		Find(&violations).Error; err != nil {
		return nil, err
	}
	if len(violations) == 0 {
		return nil, gorm.ErrRecordNotFound
	}

	return violations, nil
}

func (r *Repository) ListViolations(ctx context.Context, includeAll bool) ([]ProcscanViolationEvent, error) {
	var violations []ProcscanViolationEvent
	query := r.db.WithContext(ctx)
	if !includeAll {
		query = query.Where(procscanEffectiveViolationCondition)
	}

	if err := query.Order("detected_at DESC, id DESC").Find(&violations).Error; err != nil {
		return nil, err
	}

	return violations, nil
}

func (r *Repository) DeleteViolationByID(ctx context.Context, id uint64) error {
	result := r.db.WithContext(ctx).Where("id = ?", id).Delete(&ProcscanViolationEvent{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

func (r *Repository) DeleteViolationsByNamespace(ctx context.Context, namespace string) error {
	result := r.db.WithContext(ctx).Where("namespace = ?", namespace).Delete(&ProcscanViolationEvent{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}
