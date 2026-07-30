package controller

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/bearslyricattack/CompliK/block-controller/internal/config"
)

const (
	managedResourceLabelKey   = "app.kubernetes.io/name"
	managedResourceLabelValue = "block-controller"
)

type Controller struct {
	client kubernetes.Interface
	cfg    config.Config
	queue  workqueue.RateLimitingInterface
}

func New(client kubernetes.Interface, cfg config.Config) *Controller {
	return &Controller{
		client: client,
		cfg:    cfg,
		queue:  workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
	}
}

func (c *Controller) Run(ctx context.Context) error {
	factory := informers.NewSharedInformerFactory(c.client, 0)
	informer := factory.Core().V1().Namespaces().Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.enqueue,
		UpdateFunc: func(_, newObj any) { c.enqueue(newObj) },
		DeleteFunc: c.enqueue,
	})

	stopCh := ctx.Done()
	factory.Start(stopCh)

	if ok := cache.WaitForCacheSync(stopCh, informer.HasSynced); !ok {
		return fmt.Errorf("wait for namespace cache sync failed")
	}

	go func() {
		<-ctx.Done()
		c.queue.ShutDown()
	}()

	for i := 0; i < c.cfg.WorkerCount; i++ {
		go c.runWorker(ctx)
	}

	<-ctx.Done()
	return ctx.Err()
}

func (c *Controller) runWorker(ctx context.Context) {
	for c.processNextItem(ctx) {
	}
}

func (c *Controller) processNextItem(ctx context.Context) bool {
	item, shutdown := c.queue.Get()
	if shutdown {
		return false
	}

	defer c.queue.Done(item)

	namespace, ok := item.(string)
	if !ok {
		c.queue.Forget(item)
		return true
	}

	if err := c.reconcile(ctx, namespace); err != nil {
		c.queue.AddRateLimited(namespace)
		return true
	}

	c.queue.Forget(item)
	return true
}

func (c *Controller) enqueue(obj any) {
	namespace, ok := namespaceName(obj)
	if !ok {
		return
	}

	c.queue.Add(namespace)
}

func namespaceName(obj any) (string, bool) {
	switch typed := obj.(type) {
	case *corev1.Namespace:
		name := strings.TrimSpace(typed.Name)
		return name, name != ""
	case cache.DeletedFinalStateUnknown:
		return namespaceName(typed.Obj)
	case *cache.DeletedFinalStateUnknown:
		if typed == nil {
			return "", false
		}
		return namespaceName(typed.Obj)
	default:
		return "", false
	}
}

func (c *Controller) reconcile(ctx context.Context, namespace string) error {
	ns, err := c.client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}

		return err
	}

	if ns.Labels != nil && ns.Labels[c.cfg.NamespaceLabelKey] == c.cfg.NamespaceLabelValue {
		if err := c.ensureLocked(ctx, namespace); err != nil {
			return err
		}

		return nil
	}

	return c.ensureUnlocked(ctx, namespace)
}

func (c *Controller) ensureLocked(ctx context.Context, namespace string) error {
	if err := c.ensureNetworkPolicy(ctx, namespace); err != nil {
		return err
	}

	return c.ensureResourceQuota(ctx, namespace)
}

func (c *Controller) ensureUnlocked(ctx context.Context, namespace string) error {
	if err := c.deleteNetworkPolicy(ctx, namespace); err != nil {
		return err
	}

	return c.deleteResourceQuota(ctx, namespace)
}

func (c *Controller) ensureNetworkPolicy(ctx context.Context, namespace string) error {
	desired := lockedNetworkPolicy(namespace, c.cfg.NetworkPolicyName)
	current, err := c.client.NetworkingV1().NetworkPolicies(namespace).Get(ctx, desired.Name, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, err = c.client.NetworkingV1().NetworkPolicies(namespace).Create(ctx, desired, metav1.CreateOptions{})
			return err
		}

		return err
	}

	if err := requireManagedResource("NetworkPolicy", namespace, desired.Name, current.Labels); err != nil {
		return err
	}

	current.Spec = desired.Spec
	current.Labels = desired.Labels
	_, err = c.client.NetworkingV1().NetworkPolicies(namespace).Update(ctx, current, metav1.UpdateOptions{})
	return err
}

func (c *Controller) deleteNetworkPolicy(ctx context.Context, namespace string) error {
	current, err := c.client.NetworkingV1().NetworkPolicies(namespace).Get(ctx, c.cfg.NetworkPolicyName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}

		return err
	}

	if err := requireManagedResource("NetworkPolicy", namespace, c.cfg.NetworkPolicyName, current.Labels); err != nil {
		return err
	}

	err = c.client.NetworkingV1().NetworkPolicies(namespace).Delete(ctx, c.cfg.NetworkPolicyName, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	return nil
}

func (c *Controller) ensureResourceQuota(ctx context.Context, namespace string) error {
	desired := lockedResourceQuota(namespace, c.cfg.ResourceQuotaName)
	current, err := c.client.CoreV1().ResourceQuotas(namespace).Get(ctx, desired.Name, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, err = c.client.CoreV1().ResourceQuotas(namespace).Create(ctx, desired, metav1.CreateOptions{})
			return err
		}

		return err
	}

	if err := requireManagedResource("ResourceQuota", namespace, desired.Name, current.Labels); err != nil {
		return err
	}

	current.Spec = desired.Spec
	current.Labels = desired.Labels
	_, err = c.client.CoreV1().ResourceQuotas(namespace).Update(ctx, current, metav1.UpdateOptions{})
	return err
}

func (c *Controller) deleteResourceQuota(ctx context.Context, namespace string) error {
	current, err := c.client.CoreV1().ResourceQuotas(namespace).Get(ctx, c.cfg.ResourceQuotaName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}

		return err
	}

	if err := requireManagedResource("ResourceQuota", namespace, c.cfg.ResourceQuotaName, current.Labels); err != nil {
		return err
	}

	err = c.client.CoreV1().ResourceQuotas(namespace).Delete(ctx, c.cfg.ResourceQuotaName, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	return nil
}

func lockedNetworkPolicy(namespace, name string) *networkingv1.NetworkPolicy {
	policyTypeIngress := networkingv1.PolicyTypeIngress
	policyTypeEgress := networkingv1.PolicyTypeEgress

	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name": "block-controller",
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{policyTypeIngress, policyTypeEgress},
		},
	}
}

func lockedResourceQuota(namespace, name string) *corev1.ResourceQuota {
	return &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name": "block-controller",
			},
		},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				corev1.ResourcePods:     resource.MustParse("0"),
				corev1.ResourceServices: resource.MustParse("0"),
			},
		},
	}
}

func requireManagedResource(kind, namespace, name string, labels map[string]string) error {
	if labels[managedResourceLabelKey] == managedResourceLabelValue {
		return nil
	}

	return fmt.Errorf("%s %s/%s is not managed by block-controller", kind, namespace, name)
}
