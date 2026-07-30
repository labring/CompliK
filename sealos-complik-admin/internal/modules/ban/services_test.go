//nolint:testpackage // Tests set unexported service clock and inspect unexported model fields.
package ban

import (
	"context"
	"errors"
	"testing"
	"time"

	"sealos-complik-admin/internal/infra/k8s"
	"sealos-complik-admin/internal/modules/pagequery"
)

type fakeBanRepository struct {
	created []*Ban
}

func (f *fakeBanRepository) CreateBan(ctx context.Context, ban *Ban) error {
	f.created = append(f.created, ban)
	ban.ID = uint64(len(f.created))
	return nil
}

func (f *fakeBanRepository) DeleteBanByID(context.Context, uint64) error {
	return nil
}

func (f *fakeBanRepository) GetBansByNamespace(context.Context, string) ([]Ban, error) {
	return nil, nil
}

func (f *fakeBanRepository) ListBans(context.Context) ([]Ban, error) {
	return nil, nil
}

func (f *fakeBanRepository) ListBansPage(
	context.Context,
	pagequery.Options,
	string,
	string,
) ([]Ban, int64, error) {
	return nil, 0, nil
}

func (f *fakeBanRepository) HasActiveBan(context.Context, string, time.Time) (bool, error) {
	return false, nil
}

type failingNamespaceLocker struct {
	called bool
}

func (l *failingNamespaceLocker) EnsureLocked(context.Context, string) (bool, error) {
	l.called = true
	return false, errors.New("label patch failed")
}

func (l *failingNamespaceLocker) EnsureUnlocked(context.Context, string) (bool, error) {
	return false, nil
}

func TestCreateBanKeepsRecordWhenLabelFails(t *testing.T) {
	repo := &fakeBanRepository{}
	locker := &failingNamespaceLocker{}
	svc := NewService(repo, nil, "", locker)
	svc.now = func() time.Time { return time.Date(2026, time.July, 29, 8, 0, 0, 0, time.UTC) }

	err := svc.CreateBan(context.Background(), CreateBanRequest{
		Namespace:    "demo-ns",
		Reason:       "manual ban",
		BanStartTime: svc.now(),
		OperatorName: "admin",
	})
	if err == nil {
		t.Fatal("expected label failure")
	}

	if !locker.called {
		t.Fatal("expected namespace locker to be called")
	}

	if len(repo.created) != 1 {
		t.Fatalf("expected ban record to be created, got %d", len(repo.created))
	}

	if repo.created[0].Namespace != "demo-ns" {
		t.Fatalf("unexpected ban namespace: %q", repo.created[0].Namespace)
	}
}

var _ k8s.NamespaceLocker = (*failingNamespaceLocker)(nil)
