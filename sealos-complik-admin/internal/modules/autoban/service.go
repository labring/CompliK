package autoban

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"sealos-complik-admin/internal/modules/ban"
)

type BanService interface {
	CreateBan(ctx context.Context, req ban.CreateBanRequest) error
	GetBanStatus(ctx context.Context, namespace string) (*ban.BanStatusResponse, error)
}

type Service struct {
	policyRepository policyRepository
	banService       BanService
	now              func() time.Time
}

type Handler interface {
	HandleViolation(ctx context.Context, violation Violation) error
}

func NewService(policyRepository policyRepository, banService BanService) *Service {
	return &Service{
		policyRepository: policyRepository,
		banService:       banService,
		now:              time.Now,
	}
}

func (s *Service) HandleViolation(ctx context.Context, violation Violation) error {
	if s == nil || s.banService == nil {
		return nil
	}

	if !violation.IsIllegal || violation.IsTest {
		return nil
	}

	policy := loadPolicy(ctx, s.policyRepository)
	if !policy.Enabled {
		return nil
	}

	if !policy.allowsSource(violation.Source) || !policy.allowsNamespace(violation.Namespace) {
		return nil
	}

	if processName := strings.TrimSpace(violation.ProcessName); processName != "" &&
		!policy.allowsProcessName(processName) {
		return nil
	}

	status, err := s.banService.GetBanStatus(ctx, strings.TrimSpace(violation.Namespace))
	if err != nil {
		log.Printf("autoban: failed to check active ban for %s: %v", violation.Namespace, err)
		return err
	}

	if status != nil && status.Banned {
		return nil
	}

	if policy.DryRun {
		log.Printf(
			"autoban: dry-run would ban namespace %s from %s",
			violation.Namespace,
			violation.Source,
		)

		return nil
	}

	req := ban.CreateBanRequest{
		Namespace:    strings.TrimSpace(violation.Namespace),
		Reason:       s.buildReason(policy, violation),
		BanStartTime: s.now().UTC(),
		OperatorName: policy.OperatorName,
	}

	if err := s.banService.CreateBan(ctx, req); err != nil {
		log.Printf("autoban: failed to create ban for %s: %v", violation.Namespace, err)
		return err
	}

	return nil
}

func (s *Service) buildReason(policy Policy, violation Violation) string {
	var builder strings.Builder
	builder.WriteString(policy.ReasonPrefix)
	builder.WriteString(": ")
	builder.WriteString(string(violation.Source))
	builder.WriteString(" violation")

	if namespace := strings.TrimSpace(violation.Namespace); namespace != "" {
		builder.WriteString(" in ")
		builder.WriteString(namespace)
	}

	if detector := strings.TrimSpace(violation.DetectorName); detector != "" {
		builder.WriteString("\nDetector: ")
		builder.WriteString(detector)
	}

	if summary := strings.TrimSpace(violation.Summary); summary != "" {
		builder.WriteString("\nSummary: ")
		builder.WriteString(summary)
	}

	if detail := strings.TrimSpace(violation.Detail); detail != "" {
		builder.WriteString("\nDetail: ")
		builder.WriteString(detail)
	}

	if !violation.DetectedAt.IsZero() {
		builder.WriteString("\nDetected at: ")
		builder.WriteString(violation.DetectedAt.UTC().Format(time.RFC3339))
	}

	return builder.String()
}

func (s *Service) String() string {
	return fmt.Sprintf("autoban.Service<%p>", s)
}
