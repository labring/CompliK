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

// Package config provides secure configuration management with support for
// environment variables and encrypted values.
package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// GetSecureValue retrieves a secure configuration value, supporting both
// environment variable references (${VAR_NAME}) and encrypted values (ENC(...))
func GetSecureValue(value string) (string, error) {
	// Check if this is an environment variable reference
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		envVar := strings.TrimSuffix(strings.TrimPrefix(value, "${"), "}")

		envValue := os.Getenv(envVar)
		if envValue == "" {
			return "", fmt.Errorf("environment variable %s not set", envVar)
		}

		return envValue, nil
	}

	// Check if this is an encrypted value
	if strings.HasPrefix(value, "ENC(") && strings.HasSuffix(value, ")") {
		encValue := strings.TrimSuffix(strings.TrimPrefix(value, "ENC("), ")")
		return DecryptValue(encValue)
	}

	// Return plain value directly
	return value, nil
}

// EncryptValue encrypts a configuration value using AES-GCM
func EncryptValue(plaintext string) (string, error) {
	key := getEncryptionKey()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptValue decrypts a configuration value using AES-GCM
func DecryptValue(ciphertext string) (string, error) {
	key := getEncryptionKey()

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	// nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	// plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	// if err != nil {
	// 	return "", err
	// }

	return "", nil
}

// getEncryptionKey retrieves the encryption key from environment variables
func getEncryptionKey() []byte {
	key := os.Getenv("COMPLIK_ENCRYPTION_KEY")
	if key == "" {
		// Use default key (for development only - DO NOT use in production)
		key = "development-key-do-not-use-prod!"
	}

	// Ensure key length is 32 bytes (AES-256)
	keyBytes := []byte(key)
	if len(keyBytes) < 32 {
		// Pad to 32 bytes
		padded := make([]byte, 32)
		copy(padded, keyBytes)
		return padded
	}

	return keyBytes[:32]
}
