// Copyright 2025 CompliK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package whitelist

import (
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type WhitelistType string

const (
	WhitelistTypeNamespace WhitelistType = "namespace"
	WhitelistTypeHost      WhitelistType = "host"
)

type Whitelist struct {
	ID        uint          `gorm:"primaryKey"     json:"id"`
	Region    string        `                      json:"region"`
	Name      string        `gorm:"not null;index" json:"name"`
	Namespace string        `gorm:"index"          json:"namespace"`
	Hostname  string        `gorm:"index"          json:"hostname"`
	Type      WhitelistType `gorm:"not null;index" json:"type"`
	Remark    string        `gorm:"type:text"      json:"remark"`
	CreatedAt time.Time     `                      json:"created_at"`
	UpdatedAt time.Time     `                      json:"updated_at"`
}

func (Whitelist) TableName() string {
	return "whitelists"
}

type WhitelistService struct {
	db      *gorm.DB
	timeout time.Duration
}

func NewWhitelistService(db *gorm.DB, timeout time.Duration) *WhitelistService {
	return &WhitelistService{
		db:      db,
		timeout: timeout,
	}
}

func (s *WhitelistService) IsNamespaceWhitelisted(
	namespace, region string,
) (bool, *Whitelist, error) {
	var whitelist Whitelist

	err := s.db.Session(&gorm.Session{Logger: logger.Discard}).
		Model(&Whitelist{}).
		Where("namespace = ? AND type = ? AND region = ?", namespace, WhitelistTypeNamespace, region).
		First(&whitelist).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil, nil
		}
		return false, nil, err
	}

	return true, &whitelist, nil
}

func (s *WhitelistService) IsHostWhitelisted(host, region string) (bool, *Whitelist, error) {
	var whitelist Whitelist

	timeout := 7 * 24 * time.Hour
	if s.timeout > 0 {
		timeout = s.timeout
	}

	expireTime := time.Now().Add(-timeout)

	err := s.db.Session(&gorm.Session{Logger: logger.Discard}).
		Model(&Whitelist{}).
		Where("hostname = ? AND type = ? AND region = ? AND created_at > ?", host, WhitelistTypeHost, region, expireTime).
		First(&whitelist).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil, nil
		}
		return false, nil, err
	}

	return true, &whitelist, nil
}

func (s *WhitelistService) IsWhitelisted(namespace, host, region string) (bool, *Whitelist, error) {
	if namespace != "" {
		isNamespaceWhitelisted, whitelist, err := s.IsNamespaceWhitelisted(namespace, region)
		if err != nil {
			return false, nil, err
		}

		if isNamespaceWhitelisted {
			return true, whitelist, nil
		}
	}

	if host != "" {
		isHostWhitelisted, whitelist, err := s.IsHostWhitelisted(host, region)
		if err != nil {
			return false, nil, err
		}

		if isHostWhitelisted {
			return true, whitelist, nil
		}
	}

	return false, nil, nil
}

func (s *WhitelistService) AddNamespaceWhitelist(name, namespace, remark string) error {
	whitelist := &Whitelist{
		Name:      name,
		Namespace: namespace,
		Type:      WhitelistTypeNamespace,
		Remark:    remark,
	}

	return s.db.Create(whitelist).Error
}

func (s *WhitelistService) AddHostWhitelist(name, hostname, remark string) error {
	whitelist := &Whitelist{
		Name:     name,
		Hostname: hostname,
		Type:     WhitelistTypeHost,
		Remark:   remark,
	}

	return s.db.Create(whitelist).Error
}

func (s *WhitelistService) AddWhitelist(
	name, namespace, hostname string,
	whitelistType WhitelistType,
	remark string,
) error {
	whitelist := &Whitelist{
		Name:      name,
		Namespace: namespace,
		Hostname:  hostname,
		Type:      whitelistType,
		Remark:    remark,
	}

	return s.db.Create(whitelist).Error
}

func (s *WhitelistService) RemoveWhitelistByID(id uint) error {
	return s.db.Delete(&Whitelist{}, id).Error
}

func (s *WhitelistService) RemoveNamespaceWhitelist(namespace string) error {
	return s.db.Where("namespace = ? AND type = ?", namespace, WhitelistTypeNamespace).
		Delete(&Whitelist{}).Error
}

func (s *WhitelistService) RemoveHostWhitelist(hostname string) error {
	return s.db.Where("hostname = ? AND type = ?", hostname, WhitelistTypeHost).
		Delete(&Whitelist{}).Error
}

func (s *WhitelistService) UpdateWhitelist(
	id uint,
	name, namespace, hostname, remark string,
) error {
	updates := map[string]any{
		"name":      name,
		"namespace": namespace,
		"hostname":  hostname,
		"remark":    remark,
	}

	return s.db.Model(&Whitelist{}).Where("id = ?", id).Updates(updates).Error
}

func (s *WhitelistService) GetWhitelistByID(id uint) (*Whitelist, error) {
	var whitelist Whitelist

	err := s.db.First(&whitelist, id).Error
	if err != nil {
		return nil, err
	}

	return &whitelist, nil
}

func (s *WhitelistService) GetAllWhitelists() ([]Whitelist, error) {
	var whitelists []Whitelist

	err := s.db.Order("created_at desc").Find(&whitelists).Error
	return whitelists, err
}

func (s *WhitelistService) GetWhitelistsByType(whitelistType WhitelistType) ([]Whitelist, error) {
	var whitelists []Whitelist

	err := s.db.Where("type = ?", whitelistType).
		Order("created_at desc").
		Find(&whitelists).Error

	return whitelists, err
}

func (s *WhitelistService) GetNamespaceWhitelists() ([]Whitelist, error) {
	return s.GetWhitelistsByType(WhitelistTypeNamespace)
}

func (s *WhitelistService) GetHostWhitelists() ([]Whitelist, error) {
	return s.GetWhitelistsByType(WhitelistTypeHost)
}

func (s *WhitelistService) SearchWhitelists(keyword string) ([]Whitelist, error) {
	var whitelists []Whitelist

	err := s.db.Where("name LIKE ? OR namespace LIKE ? OR hostname LIKE ? OR remark LIKE ?",
		"%"+keyword+"%", "%"+keyword+"%", "%"+keyword+"%", "%"+keyword+"%").
		Order("created_at desc").
		Find(&whitelists).Error

	return whitelists, err
}
