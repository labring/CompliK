# Block Controller

`block-controller` watches Kubernetes namespaces for the lock label
`block.sealos.io/locked=true`.

When a namespace is locked, the controller creates:

- `NetworkPolicy/block-controller-default-deny`, which denies ingress and egress for all pods.
- `ResourceQuota/block-controller-quota`, which prevents creating new pods and services.

When the lock label is removed, the controller deletes those managed resources.

## Run

```bash
go run ./cmd
```

The controller uses `KUBECONFIG`, `$HOME/.kube/config`, or in-cluster configuration.

## Deploy

```bash
kubectl apply -f deploy/manifests/
```

The deployment runs in the `block-system` namespace. Its RBAC allows it to watch
namespaces and manage only the enforcement resources it owns:

- `NetworkPolicy`
- `ResourceQuota`

## Configuration

Environment variables:

- `BLOCK_CONTROLLER_LABEL_KEY`, default `block.sealos.io/locked`
- `BLOCK_CONTROLLER_LABEL_VALUE`, default `true`
- `BLOCK_CONTROLLER_NETWORK_POLICY_NAME`, default `block-controller-default-deny`
- `BLOCK_CONTROLLER_RESOURCE_QUOTA_NAME`, default `block-controller-quota`
- `BLOCK_CONTROLLER_WORKERS`, default `2`
