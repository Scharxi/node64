package exposure

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// Takte (Tests ersetzen sie): die Node wird alle selfEvery gelesen (kein Verkehr), zwischen zwei Geraeten pausiert der Scan.
var (
	selfEvery      = 5 * time.Minute
	scanPause      = 200 * time.Millisecond
	newScanOptions = DefaultScanOptions
)

// ErrBusy: es laeuft schon ein Lauf.
var ErrBusy = errors.New("exposure: a run is already in progress")

// RunStatus ist der Zustand der Laeufe fuer Seite und API.
type RunStatus struct {
	LastSelfAt time.Time
	LastScanAt time.Time
	SelfKnown  bool // /proc war lesbar
	Hosts      int  // Geraete des letzten Scans
	Running    bool
	LastErr    string

	UPnPAt        time.Time // letzte erfolgreiche Abfrage des Routers
	UPnPErr       string    // Grund, warum die letzte Abfrage nichts ergab ("no gateway found" oder Fehlertext)
	ExternalIP    string    // externe Adresse laut Router
	Mappings      int       // Weiterleitungen der letzten erfolgreichen Abfrage
	UPnPTruncated bool      // der Router hatte mehr Weiterleitungen als gelesen wurden
	UPnPLocation  string    // Beschreibungs-Adresse des Routers, der zuletzt erfolgreich gefragt wurde
	UPnPGateways  int       // so viele Router haben auf die Suche geantwortet (bei mehr als einem: Adresse von Hand festlegen)
}

type runState struct {
	mu         sync.Mutex
	lastSelfAt time.Time
	selfKnown  bool
	hosts      int
	running    bool
	lastErr    string

	upnpAt        time.Time
	upnpTried     time.Time // letzter Versuch (auch ohne Erfolg): bestimmt, wann wieder gefragt wird
	upnpErr       string
	externalIP    string
	mappings      int
	upnpTruncated bool
	upnpLocation  string
	upnpGateways  int
}

// Status liefert den Zustand der Laeufe.
func (m *Module) Status() RunStatus {
	m.st.mu.Lock()
	s := RunStatus{LastSelfAt: m.st.lastSelfAt, SelfKnown: m.st.selfKnown, Hosts: m.st.hosts, Running: m.st.running, LastErr: m.st.lastErr,
		UPnPAt: m.st.upnpAt, UPnPErr: m.st.upnpErr, ExternalIP: m.st.externalIP, Mappings: m.st.mappings, UPnPTruncated: m.st.upnpTruncated,
		UPnPLocation: m.st.upnpLocation, UPnPGateways: m.st.upnpGateways}
	m.st.mu.Unlock()
	s.LastScanAt = m.lastScan(context.Background())
	return s
}

func (m *Module) lastScan(ctx context.Context) time.Time {
	if m.core == nil {
		return time.Time{}
	}
	return store.ParseTime(m.core.SettingOr(ctx, setLastScan, ""))
}

func (m *Module) setErr(err error) {
	m.st.mu.Lock()
	defer m.st.mu.Unlock()
	if err == nil {
		m.st.lastErr = ""
		return
	}
	m.st.lastErr = err.Error()
}

// snapshotSelf liest die Node und speichert sie; ist /proc nicht lesbar, bleibt alles, wie es war.
func (m *Module) snapshotSelf(ctx context.Context, now time.Time) error {
	rows, known := m.readSelf(ctx)
	m.st.mu.Lock()
	m.st.lastSelfAt, m.st.selfKnown = now, known
	m.st.mu.Unlock()
	if !known {
		return nil
	}
	return m.recordSelf(ctx, now, rows)
}

// scanDue: mindestens ein Subnetz ist eingeschaltet und der letzte Scan liegt laenger zurueck als das Intervall.
func (m *Module) scanDue(ctx context.Context, now time.Time) bool {
	s := m.LoadSettings(ctx)
	if len(s.Subnets) == 0 {
		return false
	}
	last := m.lastScan(ctx)
	return last.IsZero() || now.Sub(last) >= time.Duration(s.IntervalHours)*time.Hour
}

// scanSubnets scannt die bekannten Geraete der eingeschalteten Subnetze. Ohne IPAM oder bei einem Fehler von IPAM
// passiert still nichts. Subnetze, die es in IPAM nicht mehr gibt, fallen aus den Einstellungen.
func (m *Module) scanSubnets(ctx context.Context, now time.Time) error {
	s := m.LoadSettings(ctx)
	if len(s.Subnets) == 0 || m.subnets == nil || m.hosts == nil {
		return nil
	}
	subs, err := m.subnets(ctx)
	if err != nil {
		m.log.Debug("exposure: ipam not available", "err", err)
		return nil
	}
	ports, err := ScanPorts(s.Ports)
	if err != nil {
		m.setErr(err)
		return err
	}
	exists := map[int64]bool{}
	for _, sub := range subs {
		exists[sub.ID] = true
	}
	var keep []int64
	for _, id := range s.Subnets {
		if exists[id] {
			keep = append(keep, id)
		}
	}
	if len(keep) != len(s.Subnets) {
		s.Subnets = keep
		if err := m.saveRaw(ctx, s); err != nil {
			m.log.Warn("exposure: dropping gone subnets failed", "err", err)
		}
	}
	count := 0
	for _, id := range keep {
		hosts, err := m.hosts(ctx, id)
		if err != nil {
			m.log.Debug("exposure: ipam hosts not available", "subnet", id, "err", err)
			continue
		}
		for _, h := range hosts {
			rs, err := ScanHost(ctx, h.IP, ports, newScanOptions())
			if errors.Is(err, ErrNotAllowed) {
				continue
			}
			if err != nil { // Abbruch: nichts aufnehmen, nichts als "weg" werten
				return err
			}
			if err := m.recordHost(ctx, now, h.IP, rs); err != nil {
				m.setErr(err)
				return err
			}
			count++
			if scanPause > 0 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(scanPause):
				}
			}
		}
	}
	m.st.mu.Lock()
	m.st.hosts = count
	m.st.mu.Unlock()
	m.setErr(nil)
	return m.core.SetSetting(ctx, setLastScan, store.FormatTime(now))
}

// exclusive fuehrt fn aus, wenn kein anderer Lauf aktiv ist; sonst ErrBusy.
func (m *Module) exclusive(fn func() error) error {
	if !m.runMu.TryLock() {
		return ErrBusy
	}
	m.st.mu.Lock()
	m.st.running = true
	m.st.mu.Unlock()
	defer func() {
		m.st.mu.Lock()
		m.st.running = false
		m.st.mu.Unlock()
		m.runMu.Unlock()
	}()
	return fn()
}

// runTimeout begrenzt einen Lauf (Scan eines grossen Netzes mit vielen stillen Geraeten).
const runTimeout = 30 * time.Minute

// ErrStopped: das Modul ist beendet, es startet kein Lauf mehr.
var ErrStopped = errors.New("exposure: module is stopped")

func (m *Module) setRunning(on bool) {
	m.st.mu.Lock()
	m.st.running = on
	m.st.mu.Unlock()
}

// runAll liest die Node, fragt den Router (wenn eingeschaltet) und scannt; wer es aufruft, haelt runMu.
func (m *Module) runAll(ctx context.Context, now time.Time) error {
	if err := m.snapshotSelf(ctx, now); err != nil {
		m.setErr(err)
		return err
	}
	if err := m.readUPnP(ctx, now); err != nil {
		m.setErr(err)
		return err
	}
	return m.scanSubnets(ctx, now)
}

// RunNow liest die Node und scannt sofort und wartet auf das Ende; ErrBusy, wenn schon ein Lauf aktiv ist.
func (m *Module) RunNow(ctx context.Context) error {
	return m.exclusive(func() error { return m.runAll(ctx, time.Now().UTC()) })
}

// launch fuehrt fn im Hintergrund aus, solange kein anderer Lauf aktiv ist (sonst ErrBusy, sofort). Der Lauf haengt an
// der Lebensdauer des Moduls: Stop wartet auf ihn, danach laeuft nichts mehr. Er endet spaetestens nach runTimeout.
func (m *Module) launch(fn func(ctx context.Context) error) error {
	m.mu.Lock()
	life := m.life
	if life == nil {
		life = context.Background()
	}
	if life.Err() != nil {
		m.mu.Unlock()
		return ErrStopped
	}
	if !m.runMu.TryLock() {
		m.mu.Unlock()
		return ErrBusy
	}
	m.wg.Add(1)
	m.mu.Unlock()
	m.setRunning(true)
	go func() {
		defer m.wg.Done()
		defer m.runMu.Unlock()
		defer m.setRunning(false)
		ctx, cancel := context.WithTimeout(life, runTimeout)
		defer cancel()
		if err := fn(ctx); err != nil && life.Err() == nil {
			m.log.Warn("exposure: run failed", "err", err)
			m.setErr(err)
		}
	}()
	return nil
}

// StartRun startet RunNow im Hintergrund (ein Scan kann Minuten dauern); ErrBusy, wenn schon ein Lauf aktiv ist.
func (m *Module) StartRun() error {
	return m.launch(func(ctx context.Context) error { return m.runAll(ctx, time.Now().UTC()) })
}

// tick: die Node lesen und, wenn faellig, im Hintergrund scannen (der Scan haelt das Lesen der Node nicht auf).
func (m *Module) tick(ctx context.Context, now time.Time) {
	if err := m.snapshotSelf(ctx, now); err != nil {
		m.log.Warn("exposure: reading the node failed", "err", err)
	}
	scan, upnp := m.scanDue(ctx, now), m.upnpDue(ctx, now)
	if !scan && !upnp {
		return
	}
	err := m.launch(func(ctx context.Context) error {
		if upnp {
			if err := m.readUPnP(ctx, now); err != nil {
				return err
			}
		}
		if scan {
			return m.scanSubnets(ctx, now)
		}
		return nil
	})
	if err != nil && !errors.Is(err, ErrBusy) && !errors.Is(err, ErrStopped) {
		m.log.Warn("exposure: run not started", "err", err)
	}
}

// loop liest die Node sofort und dann alle selfEvery, bis ctx endet.
func (m *Module) loop(ctx context.Context) {
	defer m.wg.Done()
	t := time.NewTicker(selfEvery)
	defer t.Stop()
	for {
		m.tick(ctx, time.Now().UTC())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
