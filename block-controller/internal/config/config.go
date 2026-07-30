package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	NamespaceLabelKey   string
	NamespaceLabelValue string
	NetworkPolicyName   string
	ResourceQuotaName   string
	WorkerCount         int
}

func Load() Config {
	cfg := Config{
		NamespaceLabelKey:   "block.sealos.io/locked",
		NamespaceLabelValue: "true",
		NetworkPolicyName:   "block-controller-default-deny",
		ResourceQuotaName:   "block-controller-quota",
		WorkerCount:         2,
	}

	if value := strings.TrimSpace(os.Getenv("BLOCK_CONTROLLER_LABEL_KEY")); value != "" {
		cfg.NamespaceLabelKey = value
	}

	if value := strings.TrimSpace(os.Getenv("BLOCK_CONTROLLER_LABEL_VALUE")); value != "" {
		cfg.NamespaceLabelValue = value
	}

	if value := strings.TrimSpace(os.Getenv("BLOCK_CONTROLLER_NETWORK_POLICY_NAME")); value != "" {
		cfg.NetworkPolicyName = value
	}

	if value := strings.TrimSpace(os.Getenv("BLOCK_CONTROLLER_RESOURCE_QUOTA_NAME")); value != "" {
		cfg.ResourceQuotaName = value
	}

	if value := strings.TrimSpace(os.Getenv("BLOCK_CONTROLLER_WORKERS")); value != "" {
		if workers, err := strconv.Atoi(value); err == nil && workers > 0 {
			cfg.WorkerCount = workers
		}
	}

	return cfg
}
