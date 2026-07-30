//nolint:testpackage // Tests use unexported locker internals with a fake Kubernetes client.
package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestEnsureLockedPatchesNamespaceLabel(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "demo"},
	})
	locker := &namespaceLocker{client: client}

	changed, err := locker.EnsureLocked(context.Background(), " demo ")
	if err != nil {
		t.Fatalf("EnsureLocked returned error: %v", err)
	}

	if !changed {
		t.Fatal("expected namespace label to change")
	}

	namespace, err := client.CoreV1().
		Namespaces().
		Get(context.Background(), "demo", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get namespace: %v", err)
	}

	if got := namespace.Labels[NamespaceLockLabelKey]; got != NamespaceLockLabelValue {
		t.Fatalf("unexpected lock label: %q", got)
	}
}

func TestEnsureLockedSkipsAlreadyLockedNamespace(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "demo",
			Labels: map[string]string{
				NamespaceLockLabelKey: NamespaceLockLabelValue,
			},
		},
	})
	locker := &namespaceLocker{client: client}

	changed, err := locker.EnsureLocked(context.Background(), "demo")
	if err != nil {
		t.Fatalf("EnsureLocked returned error: %v", err)
	}

	if changed {
		t.Fatal("expected already locked namespace to be unchanged")
	}
}

func TestEnsureUnlockedRemovesNamespaceLabel(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "demo",
			Labels: map[string]string{
				NamespaceLockLabelKey: NamespaceLockLabelValue,
				"existing":            "label",
			},
		},
	})
	locker := &namespaceLocker{client: client}

	changed, err := locker.EnsureUnlocked(context.Background(), "demo")
	if err != nil {
		t.Fatalf("EnsureUnlocked returned error: %v", err)
	}

	if !changed {
		t.Fatal("expected namespace label to change")
	}

	namespace, err := client.CoreV1().
		Namespaces().
		Get(context.Background(), "demo", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get namespace: %v", err)
	}

	if _, ok := namespace.Labels[NamespaceLockLabelKey]; ok {
		t.Fatal("expected lock label to be removed")
	}

	if got := namespace.Labels["existing"]; got != "label" {
		t.Fatalf("unexpected existing label: %q", got)
	}
}

func TestEnsureUnlockedIgnoresMissingNamespace(t *testing.T) {
	client := fake.NewSimpleClientset()
	locker := &namespaceLocker{client: client}

	changed, err := locker.EnsureUnlocked(context.Background(), "demo")
	if err != nil {
		t.Fatalf("EnsureUnlocked returned error: %v", err)
	}

	if changed {
		t.Fatal("expected missing namespace to be unchanged")
	}

	_, err = client.CoreV1().Namespaces().Get(context.Background(), "demo", metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected namespace to stay missing, got %v", err)
	}
}
