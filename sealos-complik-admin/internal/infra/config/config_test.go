package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigAppliesDatabaseEnvOverrides(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	content := []byte(`port: 8081
database:
  host: file-host
  port: 3307
  username: file-user
  password: ""
  name: file-db
auth:
  realm: File Realm
`)
	if err := os.WriteFile(configPath, content, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("DB_HOST", "env-host")
	t.Setenv("DB_PORT", "3308")
	t.Setenv("DB_USERNAME", "root")
	t.Setenv("DB_PASSWORD", "env-password")
	t.Setenv("DB_NAME", "env-db")

	cfg := LoadConfig(configPath)

	if cfg.Database.Host != "env-host" {
		t.Fatalf("host = %q, want env-host", cfg.Database.Host)
	}
	if cfg.Database.Port != 3308 {
		t.Fatalf("port = %d, want 3308", cfg.Database.Port)
	}
	if cfg.Database.Username != "root" {
		t.Fatalf("username = %q, want root", cfg.Database.Username)
	}
	if cfg.Database.Password != "env-password" {
		t.Fatalf("password = %q, want env-password", cfg.Database.Password)
	}
	if cfg.Database.Name != "env-db" {
		t.Fatalf("name = %q, want env-db", cfg.Database.Name)
	}
}
