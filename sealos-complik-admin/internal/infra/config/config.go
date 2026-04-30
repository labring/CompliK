package config

import (
	"log"
	"os"
	"strconv"
	"strings"

	yaml "github.com/goccy/go-yaml"
)

const (
	defaultPort       = 8080
	defaultDBHost     = "localhost"
	defaultDBPort     = 3306
	defaultDBUsername = "root"
	defaultDBName     = "sealos-complik-admin"
	defaultDBPassword = "123456"
	defaultOSSPrefix  = "commitments"
	defaultAuthRealm  = "CompliK Admin"
)

type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Name     string `yaml:"name"`
}

type OSSConfig struct {
	Endpoint        string `yaml:"endpoint"`
	Bucket          string `yaml:"bucket"`
	AccessKeyID     string `yaml:"access_key_id"`
	AccessKeySecret string `yaml:"access_key_secret"`
	PublicBaseURL   string `yaml:"public_base_url"`
	ObjectPrefix    string `yaml:"object_prefix"`
}

type AuthConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Realm    string `yaml:"realm"`
}

type Config struct {
	Port     int            `yaml:"port"`
	Database DatabaseConfig `yaml:"database"`
	OSS      OSSConfig      `yaml:"oss"`
	Auth     AuthConfig     `yaml:"auth"`
}

// LoadConfig loads the configuration from the specified YAML file and environment variables.
func LoadConfig(configFile string) *Config {
	// Set default values
	cfg := &Config{
		Port: defaultPort,
		Database: DatabaseConfig{
			Host:     defaultDBHost,
			Port:     defaultDBPort,
			Username: defaultDBUsername,
			Password: defaultDBPassword, // Get DB password from environment variable
			Name:     defaultDBName,
		},
		OSS: OSSConfig{
			ObjectPrefix: defaultOSSPrefix,
		},
		Auth: AuthConfig{
			Realm: defaultAuthRealm,
		},
	}
	// Load base config from file
	if err := loadConfigInto(configFile, cfg, false); err != nil {
		log.Printf("read config file %q failed: %v, using default config", configFile, err)
	}
	applyEnvOverrides(cfg)

	return cfg
}

// loadConfigInto loads the YAML configuration from the specified file into the provided Config struct.
func loadConfigInto(configFile string, cfg *Config, optional bool) error {
	content, err := os.ReadFile(configFile)
	if err != nil {
		if optional && os.IsNotExist(err) {
			return nil
		}
		return err
	}

	if err := yaml.Unmarshal(content, cfg); err != nil {
		return err
	}

	return nil
}

func applyEnvOverrides(cfg *Config) {
	if cfg == nil {
		return
	}

	applyDatabaseEnvOverrides(cfg)
	applyAuthEnvOverrides(cfg)
}

func applyDatabaseEnvOverrides(cfg *Config) {
	if value := strings.TrimSpace(os.Getenv("DB_HOST")); value != "" {
		cfg.Database.Host = value
	}
	if value := strings.TrimSpace(os.Getenv("DB_PORT")); value != "" {
		port, err := strconv.Atoi(value)
		if err != nil {
			log.Printf("parse DB_PORT failed: %v", err)
		} else {
			cfg.Database.Port = port
		}
	}
	if value := strings.TrimSpace(os.Getenv("DB_USERNAME")); value != "" {
		cfg.Database.Username = value
	}
	if value, ok := os.LookupEnv("DB_PASSWORD"); ok {
		cfg.Database.Password = value
	}
	if value := strings.TrimSpace(os.Getenv("DB_NAME")); value != "" {
		cfg.Database.Name = value
	}
}

func applyAuthEnvOverrides(cfg *Config) {
	if value := strings.TrimSpace(os.Getenv("ADMIN_BASIC_AUTH_ENABLED")); value != "" {
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			log.Printf("parse ADMIN_BASIC_AUTH_ENABLED failed: %v", err)
		} else {
			cfg.Auth.Enabled = enabled
		}
	}
	if value := strings.TrimSpace(os.Getenv("ADMIN_BASIC_AUTH_USERNAME")); value != "" {
		cfg.Auth.Username = value
	}
	if value := strings.TrimSpace(os.Getenv("ADMIN_BASIC_AUTH_PASSWORD")); value != "" {
		cfg.Auth.Password = value
	}
	if value := strings.TrimSpace(os.Getenv("ADMIN_BASIC_AUTH_REALM")); value != "" {
		cfg.Auth.Realm = value
	}
	if strings.TrimSpace(cfg.Auth.Realm) == "" {
		cfg.Auth.Realm = defaultAuthRealm
	}
}
