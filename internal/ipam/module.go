// Package ipam ist das Modul IPAM: ein Adressverzeichnis, das sich selbst fuellt. Subnetze legt man einmal an,
// Geraete und Namen kommen aus Quellen, die die Node ohnehin kennt (DNS64, Nachbartabelle). Plan: docs/PLAN-NODE64-IPAM.md.
package ipam

import (
	"context"
	"embed"
	"log/slog"
	"net/http"
	"sync"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/store"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// changelog wird unter Einstellungen > Module angezeigt (Version siehe Info).
//
//go:embed CHANGELOG.md
var changelog string

//go:embed CHANGELOG.en.md
var changelogEN string

// Name ist der technische Schluessel des Moduls.
const Name = "ipam"

const version = "0.1.0"

// Module implementiert module.Module.
type Module struct {
	core        *store.Store
	log         *slog.Logger
	nodeVersion string

	g module.Guards

	src sourceBook // Quellen und ihr Zustand (source.go)

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New erzeugt das Modul.
func New(core *store.Store, log *slog.Logger, nodeVersion string) *Module {
	return &Module{core: core, log: log.With("module", Name), nodeVersion: nodeVersion}
}

func (m *Module) Info() module.Info {
	return module.Info{Name: Name, TitleKey: "nav.ipam", Icon: "bi-diagram-3", Path: "/ipam", Available: true, Order: 45,
		Version: version, Changelog: changelog, ChangelogEN: changelogEN}
}

func (m *Module) Migrations() []store.Migration {
	ms, err := store.ReadMigrations(migrationFS, "migrations")
	if err != nil {
		panic(err)
	}
	return ms
}

// Routes merkt die Guards und registriert Seite und API.
func (m *Module) Routes(mux *http.ServeMux, g module.Guards) {
	m.g = g
	m.uiRoutes(mux, g)
	m.apiRoutes(mux, g)
}

// Start startet die Abfrage der Quellen.
func (m *Module) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.loop(ctx)
	m.log.Info("ipam started", "poll", pollEvery.String())
	return nil
}

// Stop beendet alle Goroutinen des Moduls.
func (m *Module) Stop(ctx context.Context) error {
	m.mu.Lock()
	cancel := m.cancel
	m.cancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}
