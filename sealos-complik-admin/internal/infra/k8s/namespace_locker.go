package k8s

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
)

const (
	NamespaceLockLabelKey    = "block.sealos.io/locked"
	NamespaceLockLabelValue  = "true"
	defaultKubeConfigEnvName = "KUBECONFIG"
)

type NamespaceLocker interface {
	EnsureLocked(ctx context.Context, namespace string) (bool, error)
	EnsureUnlocked(ctx context.Context, namespace string) (bool, error)
}

type namespaceLocker struct {
	client kubernetes.Interface
}

type noopNamespaceLocker struct{}

func NewNamespaceLocker() (NamespaceLocker, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}

	return &namespaceLocker{client: client}, nil
}

func NewNoopNamespaceLocker() NamespaceLocker {
	return noopNamespaceLocker{}
}

func (l *namespaceLocker) EnsureLocked(ctx context.Context, namespace string) (bool, error) {
	return l.ensureLabel(ctx, namespace, true)
}

func (l *namespaceLocker) EnsureUnlocked(ctx context.Context, namespace string) (bool, error) {
	return l.ensureLabel(ctx, namespace, false)
}

func (l *namespaceLocker) ensureLabel(
	ctx context.Context,
	namespace string,
	lock bool,
) (bool, error) {
	trimmedNamespace := strings.TrimSpace(namespace)
	if trimmedNamespace == "" {
		return false, errors.New("namespace is required")
	}

	changed := false

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		target, err := l.client.CoreV1().
			Namespaces().
			Get(ctx, trimmedNamespace, metav1.GetOptions{})
		if err != nil {
			if !lock && apierrors.IsNotFound(err) {
				return nil
			}

			return err
		}

		target = target.DeepCopy()

		labels := target.GetLabels()
		if labels == nil {
			labels = map[string]string{}
		}

		if lock {
			if labels[NamespaceLockLabelKey] == NamespaceLockLabelValue {
				return nil
			}

			labels[NamespaceLockLabelKey] = NamespaceLockLabelValue
			target.SetLabels(labels)

			changed = true
			_, err = l.client.CoreV1().Namespaces().Update(ctx, target, metav1.UpdateOptions{})

			return err
		}

		if _, ok := labels[NamespaceLockLabelKey]; !ok {
			return nil
		}

		delete(labels, NamespaceLockLabelKey)
		target.SetLabels(labels)

		changed = true
		_, err = l.client.CoreV1().Namespaces().Update(ctx, target, metav1.UpdateOptions{})

		return err
	})
	if err != nil {
		return false, err
	}

	return changed, nil
}

func (noopNamespaceLocker) EnsureLocked(context.Context, string) (bool, error) {
	return false, nil
}

func (noopNamespaceLocker) EnsureUnlocked(context.Context, string) (bool, error) {
	return false, nil
}

func loadConfig() (*rest.Config, error) {
	if kubeconfig := strings.TrimSpace(os.Getenv(defaultKubeConfigEnvName)); kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}

	if home, err := os.UserHomeDir(); err == nil {
		path := filepath.Join(home, ".kube", "config")
		if _, statErr := os.Stat(path); statErr == nil {
			return clientcmd.BuildConfigFromFlags("", path)
		}
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubernetes config: %w", err)
	}

	return cfg, nil
}
