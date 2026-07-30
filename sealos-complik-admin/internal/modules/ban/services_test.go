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
	created    []*Ban
	deletedIDs []uint64
}

func (f *fakeBanRepository) CreateBan(ctx context.Context, ban *Ban) error {
	f.created = append(f.created, ban)
	ban.ID = uint64(len(f.created))
	return nil
}

func (f *fakeBanRepository) DeleteBanByID(ctx context.Context, id uint64) error {
	f.deletedIDs = append(f.deletedIDs, id)

	filtered := f.created[:0]
	for _, ban := range f.created {
		if ban.ID == id {
			continue
		}

		filtered = append(filtered, ban)
	}

	f.created = filtered

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

func TestCreateBanRollsBackRecordWhenLabelFails(t *testing.T) {
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

	if len(repo.created) != 0 {
		t.Fatalf("expected ban record to be rolled back, got %d", len(repo.created))
	}

	if len(repo.deletedIDs) != 1 {
		t.Fatalf("expected 1 rollback delete, got %d", len(repo.deletedIDs))
	}

	if repo.deletedIDs[0] != 1 {
		t.Fatalf("unexpected rollback delete id: %d", repo.deletedIDs[0])
	}
}

var _ k8s.NamespaceLocker = (*failingNamespaceLocker)(nil)
