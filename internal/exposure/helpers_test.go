package exposure

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

// newTestModule legt Store und Tabelle an (Kern und Modul), ohne das Modul zu starten.
func newTestModule(t *testing.T) *Module {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	core, err := store.Open(ctx, filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	cm, _ := store.CoreMigrations()
	if err := core.Migrate(ctx, "core", cm); err != nil {
		t.Fatal(err)
	}
	m := New(core, log, "test")
	if err := core.Migrate(ctx, Name, m.Migrations()); err != nil {
		t.Fatal(err)
	}
	return m
}
