// Package exposure ist das Modul Exposure-Check: zeigt, auf welcher IP-Adresse welche Ports offen sind bzw. gehoert
// wird (Spur 1, Innen-Sicht): die Node selbst aus /proc und bekannte Geraete der IPAM-Subnetze per TCP-Connect-Scan.
// Plan: docs/PLAN-NODE64-EXPOSURE.md.
package exposure

import (
	"context"
	"embed"
	"log/slog"
	"net/http"
	"sync"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/netstat"
	"github.com/ipv64net/node64/internal/ports"
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
const Name = "exposure"

const version = "0.1.0"

// Module implementiert module.Module.
type Module struct {
	core        *store.Store
	log         *slog.Logger
	nodeVersion string

	g module.Guards

	listeners func() ([]netstat.Listener, bool)                            // lauschende Sockets der Node (Tests ersetzen sie)
	claims    func(ctx context.Context) []ports.Claim                      // Port-Verwaltung: wem gehoert welcher Port
	subnets   func(ctx context.Context) ([]SubnetRef, error)               // IPAM: Subnetze (nil = nicht verfuegbar)
	hosts     func(ctx context.Context, subnetID int64) ([]HostRef, error) // IPAM: bekannte Geraete eines Subnetzes

	runMu sync.Mutex // ein Lauf (Scan) gleichzeitig
	st    runState

	mu     sync.Mutex
	cancel context.CancelFunc
	life   context.Context // Lebensdauer des Moduls (Laeufe aus der Oberflaeche haengen daran)
	wg     sync.WaitGroup
}

// New erzeugt das Modul.
func New(core *store.Store, log *slog.Logger, nodeVersion string) *Module {
	return &Module{core: core, log: log.With("module", Name), nodeVersion: nodeVersion, listeners: netstat.Listeners}
}

func (m *Module) Info() module.Info {
	return module.Info{Name: Name, TitleKey: "nav.exposure", Icon: "bi-shield-exclamation", Path: "/exposure", Available: true, Order: 47,
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

// Start liest die Node sofort und dann im Takt selfEvery; der LAN-Scan laeuft nach dem eingestellten Intervall.
func (m *Module) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, m.cancel = context.WithCancel(ctx)
	m.life = ctx
	m.wg.Add(1)
	go m.loop(ctx)
	m.log.Info("exposure started")
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
