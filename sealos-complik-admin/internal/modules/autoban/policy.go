package autoban

import (
	"context"
	"encoding/json"
	"log"
	"slices"
	"strings"

	"sealos-complik-admin/internal/modules/projectconfig"
)

const (
	policyConfigType    = "autoban_policy"
	defaultOperatorName = "system/autoban"
	defaultReasonPrefix = "Admin auto-ban"
)

type Policy struct {
	Enabled              bool
	DryRun               bool
	OperatorName         string
	ReasonPrefix         string
	ProcessNameAllowlist []string
	ProcessNameDenylist  []string
	NamespaceAllowlist   []string
	NamespaceDenylist    []string
	Sources              SourcePolicy
}

type SourcePolicy struct {
	Complik  SourceConfig `json:"complik"`
	Procscan SourceConfig `json:"procscan"`
}

type SourceConfig struct {
	Enabled bool `json:"enabled"`
}

type policyRepository interface {
	ListProjectConfigsByType(
		ctx context.Context,
		configType string,
	) ([]projectconfig.ProjectConfig, error)
}

func defaultPolicy() Policy {
	return Policy{
		Enabled:      false,
		DryRun:       true,
		OperatorName: defaultOperatorName,
		ReasonPrefix: defaultReasonPrefix,
	}
}

func loadPolicy(ctx context.Context, repository policyRepository) Policy {
	policy := defaultPolicy()
	if repository == nil {
		return policy
	}

	configs, err := repository.ListProjectConfigsByType(ctx, policyConfigType)
	if err != nil {
		log.Printf("autoban: failed to load policy configs: %v", err)
		return policy
	}

	config := pickPolicyConfig(configs)
	if config == nil {
		return policy
	}

	if err := decodePolicy(config.ConfigValue, &policy); err != nil {
		log.Printf("autoban: failed to parse policy %q: %v", config.ConfigName, err)
		return policy
	}

	normalizePolicy(&policy)

	return policy
}

type rawPolicy struct {
	Enabled                   *bool        `json:"enabled"`
	DryRun                    *bool        `json:"dryRun"`
	DryRunSnake               *bool        `json:"dry_run"`
	OperatorName              string       `json:"operatorName"`
	OperatorNameSnake         string       `json:"operator_name"`
	ReasonPrefix              string       `json:"reasonPrefix"`
	ReasonPrefixSnake         string       `json:"reason_prefix"`
	ProcessNameAllowlist      []string     `json:"processNameAllowlist"`
	ProcessNameAllowlistSnake []string     `json:"process_name_allowlist"`
	ProcessNameDenylist       []string     `json:"processNameDenylist"`
	ProcessNameDenylistSnake  []string     `json:"process_name_denylist"`
	NamespaceAllowlist        []string     `json:"namespaceAllowlist"`
	NamespaceAllowlistSnake   []string     `json:"namespace_allowlist"`
	NamespaceDenylist         []string     `json:"namespaceDenylist"`
	NamespaceDenylistSnake    []string     `json:"namespace_denylist"`
	Sources                   SourcePolicy `json:"sources"`
}

func decodePolicy(data []byte, policy *Policy) error {
	var raw rawPolicy
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if raw.Enabled != nil {
		policy.Enabled = *raw.Enabled
	}

	if raw.DryRun != nil {
		policy.DryRun = *raw.DryRun
	} else if raw.DryRunSnake != nil {
		policy.DryRun = *raw.DryRunSnake
	}

	if raw.OperatorName != "" {
		policy.OperatorName = raw.OperatorName
	} else if raw.OperatorNameSnake != "" {
		policy.OperatorName = raw.OperatorNameSnake
	}

	if raw.ReasonPrefix != "" {
		policy.ReasonPrefix = raw.ReasonPrefix
	} else if raw.ReasonPrefixSnake != "" {
		policy.ReasonPrefix = raw.ReasonPrefixSnake
	}

	if len(raw.ProcessNameAllowlist) > 0 {
		policy.ProcessNameAllowlist = raw.ProcessNameAllowlist
	} else if len(raw.ProcessNameAllowlistSnake) > 0 {
		policy.ProcessNameAllowlist = raw.ProcessNameAllowlistSnake
	}

	if len(raw.ProcessNameDenylist) > 0 {
		policy.ProcessNameDenylist = raw.ProcessNameDenylist
	} else if len(raw.ProcessNameDenylistSnake) > 0 {
		policy.ProcessNameDenylist = raw.ProcessNameDenylistSnake
	}

	if len(raw.NamespaceAllowlist) > 0 {
		policy.NamespaceAllowlist = raw.NamespaceAllowlist
	} else if len(raw.NamespaceAllowlistSnake) > 0 {
		policy.NamespaceAllowlist = raw.NamespaceAllowlistSnake
	}

	if len(raw.NamespaceDenylist) > 0 {
		policy.NamespaceDenylist = raw.NamespaceDenylist
	} else if len(raw.NamespaceDenylistSnake) > 0 {
		policy.NamespaceDenylist = raw.NamespaceDenylistSnake
	}

	policy.Sources = raw.Sources

	return nil
}

func (c *SourceConfig) UnmarshalJSON(data []byte) error {
	var enabled bool
	if err := json.Unmarshal(data, &enabled); err == nil {
		c.Enabled = enabled
		return nil
	}

	var raw struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if raw.Enabled != nil {
		c.Enabled = *raw.Enabled
	}

	return nil
}

func pickPolicyConfig(configs []projectconfig.ProjectConfig) *projectconfig.ProjectConfig {
	if len(configs) == 0 {
		return nil
	}

	for i := range configs {
		if strings.EqualFold(strings.TrimSpace(configs[i].ConfigName), policyConfigType) {
			return &configs[i]
		}
	}

	return &configs[0]
}

func normalizePolicy(policy *Policy) {
	if policy == nil {
		return
	}

	policy.OperatorName = strings.TrimSpace(policy.OperatorName)
	if policy.OperatorName == "" {
		policy.OperatorName = defaultOperatorName
	}

	policy.ReasonPrefix = strings.TrimSpace(policy.ReasonPrefix)
	if policy.ReasonPrefix == "" {
		policy.ReasonPrefix = defaultReasonPrefix
	}

	policy.ProcessNameAllowlist = trimStrings(policy.ProcessNameAllowlist)
	policy.ProcessNameDenylist = trimStrings(policy.ProcessNameDenylist)
	policy.NamespaceAllowlist = trimStrings(policy.NamespaceAllowlist)
	policy.NamespaceDenylist = trimStrings(policy.NamespaceDenylist)
}

func trimStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	if len(result) == 0 {
		return nil
	}

	return result
}

func (p Policy) allowsNamespace(namespace string) bool {
	trimmedNamespace := strings.TrimSpace(namespace)
	if trimmedNamespace == "" {
		return false
	}

	if slices.Contains(p.NamespaceDenylist, trimmedNamespace) {
		return false
	}

	if len(p.NamespaceAllowlist) == 0 {
		return true
	}

	return slices.Contains(p.NamespaceAllowlist, trimmedNamespace)
}

func (p Policy) allowsProcessName(processName string) bool {
	trimmedProcessName := strings.TrimSpace(processName)
	if trimmedProcessName == "" {
		return true
	}

	if slices.Contains(p.ProcessNameDenylist, trimmedProcessName) {
		return false
	}

	if len(p.ProcessNameAllowlist) == 0 {
		return true
	}

	return slices.Contains(p.ProcessNameAllowlist, trimmedProcessName)
}

func (p Policy) allowsSource(source Source) bool {
	switch source {
	case SourceComplik:
		return p.Sources.Complik.Enabled
	case SourceProcscan:
		return p.Sources.Procscan.Enabled
	default:
		return false
	}
}
