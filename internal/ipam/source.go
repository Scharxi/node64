package ipam

import (
	"context"
	"sync"
	"time"
)

// Takt der Quellen und Aufraeumen (ohne Scan fragt IPAM DNS64 und die Nachbartabelle jede Minute).
var pollEvery = 60 * time.Second

const cleanupEvery = time.Hour

// Source liefert Beobachtungen aus einer Quelle (DNS64, Nachbartabelle, ...).
type Source interface {
	Name() string
	Collect(ctx context.Context) ([]Observation, error)
}

// FuncSource macht aus einer Funktion eine Quelle (so haengt main.go DNS64 an, ohne dass IPAM DNS64 kennt).
type FuncSource struct {
	N  string
	Fn func(ctx context.Context) ([]Observation, error)
}

func (f FuncSource) Name() string { return f.N }

func (f FuncSource) Collect(ctx context.Context) ([]Observation, error) { return f.Fn(ctx) }

// SourceState ist der Zustand einer Quelle beim letzten Durchlauf.
type SourceState struct {
	Name   string
	LastOK time.Time // letzter erfolgreicher Abruf
	Err    string    // Fehler des letzten Abrufs, leer = keiner
	Count  int       // Beobachtungen des letzten erfolgreichen Abrufs
}

// sourceBook haelt Quellen und Zustand; die Felder schuetzt mu.
type sourceBook struct {
	mu          sync.Mutex
	sources     []Source
	states      []SourceState
	outside     int
	lastCleanup time.Time
}

// AddSource meldet eine Quelle an. Vor Start aufrufen.
func (m *Module) AddSource(s Source) {
	m.src.mu.Lock()
	defer m.src.mu.Unlock()
	m.src.sources = append(m.src.sources, s)
	m.src.states = append(m.src.states, SourceState{Name: s.Name()})
}

// SourceStatus liefert den Zustand der Quellen in der Reihenfolge der Anmeldung.
func (m *Module) SourceStatus() []SourceState {
	m.src.mu.Lock()
	defer m.src.mu.Unlock()
	return append([]SourceState(nil), m.src.states...)
}

// Outside ist die Zahl der Adressen ausserhalb aller Subnetze beim letzten Durchlauf.
func (m *Module) Outside() int {
	m.src.mu.Lock()
	defer m.src.mu.Unlock()
	return m.src.outside
}

// pollOnce fragt alle Quellen ab und nimmt die Beobachtungen auf. Eine ausfallende Quelle stoppt die anderen nicht.
// Hoechstens stuendlich wird aufgeraeumt.
func (m *Module) pollOnce(ctx context.Context, now time.Time) {
	m.src.mu.Lock()
	sources := append([]Source(nil), m.src.sources...)
	m.src.mu.Unlock()

	var all []Observation
	states := make([]SourceState, len(sources))
	for i, s := range sources {
		obs, err := s.Collect(ctx)
		m.src.mu.Lock()
		st := m.src.states[i]
		m.src.mu.Unlock()
		if err != nil {
			st.Err = err.Error()
			m.log.Warn("ipam source failed", "source", s.Name(), "err", err)
		} else {
			st.Err, st.LastOK, st.Count = "", now, len(obs)
			all = append(all, obs...)
		}
		states[i] = st
	}
	res, err := m.Ingest(ctx, now, all)
	if err != nil {
		m.log.Error("ipam ingest failed", "err", err)
	}
	m.src.mu.Lock()
	copy(m.src.states, states)
	if err == nil {
		m.src.outside = res.Outside
	}
	due := now.Sub(m.src.lastCleanup) >= cleanupEvery
	if due {
		m.src.lastCleanup = now
	}
	m.src.mu.Unlock()
	if due {
		if n, err := m.Cleanup(ctx, now); err != nil {
			m.log.Error("ipam cleanup failed", "err", err)
		} else if n > 0 {
			m.log.Info("ipam cleanup", "removed", n)
		}
	}
}

// loop fragt die Quellen sofort und dann im Takt pollEvery ab, bis ctx endet.
func (m *Module) loop(ctx context.Context) {
	defer m.wg.Done()
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	for {
		m.pollOnce(ctx, time.Now().UTC())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
