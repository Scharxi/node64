package exposure

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/store"
)

// Werte der Spalte notified: noch offen, ausgewertet (still), ausgewertet und gemeldet.
const (
	notifyPending   = 0
	notifyProcessed = 1
	notifyReported  = 2
)

const (
	notifySubjectMax = 5              // so viele Eintraege nennt der Betreff
	notifyListMax    = 10             // so viele Eintraege nennt der Text
	notifyQuiet      = 24 * time.Hour // dieselbe Aenderung wird hoechstens einmal je 24 Stunden gemeldet
)

// SetNotifier bindet die Meldungen an (nil = keine; dann werden Ereignisse auch nicht als ausgewertet markiert).
func (m *Module) SetNotifier(f func(notify.Alert)) {
	m.notifyMu.Lock()
	m.notifier = f
	m.notifyMu.Unlock()
}

// notifyItem ist eine Aenderung, die in eine Meldung kommt.
type notifyItem struct {
	id                  int64
	kind                string // Art der Meldung (notify.Kind...)
	proto, address, key string
	port                int
	text                string // Zeile fuer den Text der Meldung
}

// notifyChanges wertet die offenen Ereignisse aus und meldet je Art eine gebuendelte Meldung. Jedes Ereignis wird
// hoechstens einmal ausgewertet: die Markierung steht in der Datenbank, bevor gesendet wird (ein Neustart meldet nichts nach).
func (m *Module) notifyChanges(ctx context.Context) error {
	m.notifyMu.Lock()
	defer m.notifyMu.Unlock()
	if m.notifier == nil {
		return nil
	}
	events, err := m.pendingEvents(ctx)
	if err != nil || len(events) == 0 {
		return err
	}
	s := m.LoadSettings(ctx)
	view, err := m.notifyView(ctx)
	if err != nil {
		return err
	}
	var items []notifyItem
	status := map[int64]int{}
	taken := map[string]bool{}
	for _, ev := range events {
		status[ev.ID] = notifyProcessed
		it, ok := view.item(ev, s)
		if !ok || taken[it.key] {
			continue
		}
		quiet, err := m.recentlyReported(ctx, ev)
		if err != nil {
			return err
		}
		if quiet {
			continue
		}
		taken[it.key] = true
		status[ev.ID] = notifyReported
		items = append(items, it)
	}
	if err := m.markEvents(ctx, status); err != nil {
		return err
	}
	byKind := map[string][]notifyItem{}
	var order []string
	for _, it := range items {
		if _, ok := byKind[it.kind]; !ok {
			order = append(order, it.kind)
		}
		byKind[it.kind] = append(byKind[it.kind], it)
	}
	for _, kind := range order {
		m.notifier(buildAlert(notify.Kind(kind), byKind[kind], time.Now().UTC(), m.alertSeq.Add(1)))
	}
	return nil
}

// notifyViewData ist der Stand, gegen den ein Ereignis eingeordnet wird.
type notifyViewData struct {
	open   map[string]OverviewRow // offene Weiterleitungen nach proto/port
	listen map[listenKey]bool     // offene lauschende Ports
}

func (m *Module) notifyView(ctx context.Context) (notifyViewData, error) {
	v := notifyViewData{open: map[string]OverviewRow{}, listen: map[listenKey]bool{}}
	rows, err := m.Listening(ctx, "")
	if err != nil {
		return v, err
	}
	ext, err := m.Externals(ctx)
	if err != nil {
		return v, err
	}
	exp, err := m.Expecteds(ctx)
	if err != nil {
		return v, err
	}
	for _, l := range rows {
		if l.State == "open" {
			v.listen[listenKey{l.Address, l.Proto, l.Port}] = true
		}
	}
	var local = m.localAddrs
	in := OverviewInput{External: ext, Listen: rows, Expected: exp, Now: time.Now().UTC()}
	if local != nil {
		in.Local = local()
	}
	open, _ := Classify(in)
	for _, r := range open {
		v.open[portKey(r.Proto, r.Port)] = r
	}
	return v, nil
}

// item ordnet ein Ereignis einer Meldung zu (false = keine Meldung, das Ereignis gilt als ausgewertet).
func (v notifyViewData) item(ev Event, s Settings) (notifyItem, bool) {
	it := notifyItem{id: ev.ID, proto: ev.Proto, port: ev.Port, address: ev.Address}
	switch ev.Kind {
	case EventForwardNew:
		row, ok := v.open[portKey(ev.Proto, ev.Port)]
		if !ok { // schon wieder weg
			return it, false
		}
		switch {
		case row.Class == ClassUnexpected && s.NotifyUnexpected:
			it.kind = string(notify.KindExposureUnexpected)
		case row.Class == ClassExpected && s.NotifyNew:
			it.kind = string(notify.KindExposureNew)
		default:
			return it, false
		}
		it.text = portKey(ev.Proto, ev.Port) + " → " + ev.Detail
	case EventListenNew:
		if !s.NotifyListen || !v.listen[listenKey{ev.Address, ev.Proto, ev.Port}] {
			return it, false
		}
		it.kind = string(notify.KindExposureListen)
		it.text = portKey(ev.Proto, ev.Port) + " (" + ev.Address + ")"
	default:
		return it, false
	}
	it.key = it.kind + "|" + ev.Proto + "|" + strconv.Itoa(ev.Port) + "|" + ev.Address
	return it, true
}

func (m *Module) pendingEvents(ctx context.Context) ([]Event, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT id, at, kind, proto, port, address, detail FROM exposure_events WHERE notified = ? ORDER BY id ASC`, notifyPending)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var at string
		if err := rows.Scan(&e.ID, &at, &e.Kind, &e.Proto, &e.Port, &e.Address, &e.Detail); err != nil {
			return nil, err
		}
		e.At = store.ParseTime(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// recentlyReported: dieselbe Aenderung (Art, Protokoll, Port, Adresse) wurde in den 24 Stunden davor schon gemeldet.
func (m *Module) recentlyReported(ctx context.Context, ev Event) (bool, error) {
	var n int
	err := m.core.Reader().QueryRowContext(ctx, `SELECT count(*) FROM exposure_events WHERE notified = ? AND kind = ? AND proto = ? AND port = ? AND address = ? AND id < ? AND at >= ?`,
		notifyReported, ev.Kind, ev.Proto, ev.Port, ev.Address, ev.ID, store.FormatTime(ev.At.Add(-notifyQuiet))).Scan(&n)
	return n > 0, err
}

func (m *Module) markEvents(ctx context.Context, status map[int64]int) error {
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for id, st := range status {
		if _, err := tx.ExecContext(ctx, `UPDATE exposure_events SET notified = ? WHERE id = ?`, st, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// buildAlert buendelt die Aenderungen einer Art zu einer Meldung; Betreff und Text nennen nur die ersten Eintraege.
func buildAlert(kind notify.Kind, items []notifyItem, now time.Time, seq uint64) notify.Alert {
	names := make([]string, 0, notifySubjectMax)
	lines := make([]string, 0, notifyListMax)
	for i, it := range items {
		if i < notifySubjectMax {
			names = append(names, portKey(it.proto, it.port))
		}
		if i < notifyListMax {
			lines = append(lines, it.text)
		}
	}
	name, list := strings.Join(names, ", "), strings.Join(lines, ", ")
	if len(items) > notifySubjectMax {
		name += " …"
	}
	if len(items) > notifyListMax {
		list += " …"
	}
	return notify.Alert{
		EventID: "exposure-" + string(kind) + "-" + strconv.FormatInt(now.UnixNano(), 36) + "-" + strconv.FormatUint(seq, 36), Kind: kind, Time: now,
		Check: notify.CheckInfo{Name: name, NotifyDown: true, NotifyUp: true, Local: true},
		Data:  map[string]string{"text": "notify.text." + string(kind), "count": strconv.Itoa(len(items)), "list": list},
	}
}
