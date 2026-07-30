package controller

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"github.com/bearslyricattack/CompliK/block-controller/internal/config"
)

func TestReconcileLockedNamespaceCreatesEnforcementResources(t *testing.T) {
	cfg := testConfig()
	client := fake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "demo",
			Labels: map[string]string{
				cfg.NamespaceLabelKey: cfg.NamespaceLabelValue,
			},
		},
	})
	ctrl := New(client, cfg)

	if err := ctrl.reconcile(context.Background(), "demo"); err != nil {
		t.Fatalf("reconcile returned error: %v", err)
	}

	policy, err := client.NetworkingV1().NetworkPolicies("demo").Get(
		context.Background(),
		cfg.NetworkPolicyName,
		metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("get network policy: %v", err)
	}
	if len(policy.Spec.PolicyTypes) != 2 {
		t.Fatalf("unexpected policy types: %+v", policy.Spec.PolicyTypes)
	}

	quota, err := client.CoreV1().ResourceQuotas("demo").Get(
		context.Background(),
		cfg.ResourceQuotaName,
		metav1.GetOptions{},
	)
	if err != nil {
		t.Fatalf("get resource quota: %v", err)
	}
	podQuota := quota.Spec.Hard[corev1.ResourcePods]
	if got := podQuota.String(); got != "0" {
		t.Fatalf("unexpected pod quota: %s", got)
	}
}

func TestReconcileUnlockedNamespaceDeletesEnforcementResources(t *testing.T) {
	cfg := testConfig()
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo"}},
		lockedNetworkPolicy("demo", cfg.NetworkPolicyName),
		lockedResourceQuota("demo", cfg.ResourceQuotaName),
	)
	ctrl := New(client, cfg)

	if err := ctrl.reconcile(context.Background(), "demo"); err != nil {
		t.Fatalf("reconcile returned error: %v", err)
	}

	_, err := client.NetworkingV1().NetworkPolicies("demo").Get(
		context.Background(),
		cfg.NetworkPolicyName,
		metav1.GetOptions{},
	)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected network policy to be deleted, got %v", err)
	}

	_, err = client.CoreV1().ResourceQuotas("demo").Get(
		context.Background(),
		cfg.ResourceQuotaName,
		metav1.GetOptions{},
	)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected resource quota to be deleted, got %v", err)
	}
}

func TestEnsureNetworkPolicyRejectsUnmanagedResource(t *testing.T) {
	cfg := testConfig()
	client := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "demo",
				Labels: map[string]string{
					cfg.NamespaceLabelKey: cfg.NamespaceLabelValue,
				},
			},
		},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cfg.NetworkPolicyName,
				Namespace: "demo",
			},
		},
	)
	ctrl := New(client, cfg)

	err := ctrl.ensureNetworkPolicy(context.Background(), "demo")
	if err == nil || !strings.Contains(err.Error(), "not managed by block-controller") {
		t.Fatalf("expected ownership error, got %v", err)
	}
}

func TestDeleteNetworkPolicyRejectsUnmanagedResource(t *testing.T) {
	cfg := testConfig()
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo"}},
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cfg.NetworkPolicyName,
				Namespace: "demo",
			},
		},
	)
	ctrl := New(client, cfg)

	err := ctrl.deleteNetworkPolicy(context.Background(), "demo")
	if err == nil || !strings.Contains(err.Error(), "not managed by block-controller") {
		t.Fatalf("expected ownership error, got %v", err)
	}
}

func TestEnsureResourceQuotaRejectsUnmanagedResource(t *testing.T) {
	cfg := testConfig()
	client := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "demo",
				Labels: map[string]string{
					cfg.NamespaceLabelKey: cfg.NamespaceLabelValue,
				},
			},
		},
		&corev1.ResourceQuota{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cfg.ResourceQuotaName,
				Namespace: "demo",
			},
		},
	)
	ctrl := New(client, cfg)

	err := ctrl.ensureResourceQuota(context.Background(), "demo")
	if err == nil || !strings.Contains(err.Error(), "not managed by block-controller") {
		t.Fatalf("expected ownership error, got %v", err)
	}
}

func TestDeleteResourceQuotaRejectsUnmanagedResource(t *testing.T) {
	cfg := testConfig()
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo"}},
		&corev1.ResourceQuota{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cfg.ResourceQuotaName,
				Namespace: "demo",
			},
		},
	)
	ctrl := New(client, cfg)

	err := ctrl.deleteResourceQuota(context.Background(), "demo")
	if err == nil || !strings.Contains(err.Error(), "not managed by block-controller") {
		t.Fatalf("expected ownership error, got %v", err)
	}
}

func TestLockedNetworkPolicy(t *testing.T) {
	policy := lockedNetworkPolicy("demo", "deny-all")
	if policy.Name != "deny-all" || policy.Namespace != "demo" {
		t.Fatalf("unexpected metadata: %+v", policy.ObjectMeta)
	}
	if len(policy.Spec.PolicyTypes) != 2 {
		t.Fatalf("unexpected policy types: %+v", policy.Spec.PolicyTypes)
	}
	if policy.Spec.PolicyTypes[0] != networkingv1.PolicyTypeIngress ||
		policy.Spec.PolicyTypes[1] != networkingv1.PolicyTypeEgress {
		t.Fatalf("unexpected policy types: %+v", policy.Spec.PolicyTypes)
	}
}

func TestLockedResourceQuota(t *testing.T) {
	quota := lockedResourceQuota("demo", "quota")
	if quota.Name != "quota" || quota.Namespace != "demo" {
		t.Fatalf("unexpected metadata: %+v", quota.ObjectMeta)
	}
	podQuota := quota.Spec.Hard[corev1.ResourcePods]
	if got := podQuota.String(); got != "0" {
		t.Fatalf("unexpected pod quota: %s", got)
	}
	serviceQuota := quota.Spec.Hard[corev1.ResourceServices]
	if got := serviceQuota.String(); got != "0" {
		t.Fatalf("unexpected service quota: %s", got)
	}
}

func TestNamespaceName(t *testing.T) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo"}}
	name, ok := namespaceName(ns)
	if !ok || name != "demo" {
		t.Fatalf("unexpected namespace name: %q ok=%v", name, ok)
	}

	tombstone := cache.DeletedFinalStateUnknown{Obj: ns}
	name, ok = namespaceName(tombstone)
	if !ok || name != "demo" {
		t.Fatalf("unexpected tombstone name: %q ok=%v", name, ok)
	}

	pointerTombstone := &cache.DeletedFinalStateUnknown{Obj: ns}
	name, ok = namespaceName(pointerTombstone)
	if !ok || name != "demo" {
		t.Fatalf("unexpected pointer tombstone name: %q ok=%v", name, ok)
	}
}

func testConfig() config.Config {
	return config.Config{
		NamespaceLabelKey:   "block.sealos.io/locked",
		NamespaceLabelValue: "true",
		NetworkPolicyName:   "block-controller-default-deny",
		ResourceQuotaName:   "block-controller-quota",
		WorkerCount:         1,
	}
}
