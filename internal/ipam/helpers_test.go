package ipam

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/ipv64net/node64/internal/store"
)

// newTestModule legt Store und Tabellen an (Kern und Modul), ohne das Modul zu starten.
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

// mustSubnet legt ein Subnetz an oder bricht den Test ab.
func mustSubnet(t *testing.T, m *Module, name, cidr string) Subnet {
	t.Helper()
	s, err := m.AddSubnet(context.Background(), name, cidr, "")
	if err != nil {
		t.Fatalf("add subnet %s: %v", cidr, err)
	}
	return s
}
