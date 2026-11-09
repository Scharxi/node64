package exposure

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func eventsOf(t *testing.T, m *Module) []Event {
	t.Helper()
	ev, err := m.Events(context.Background(), 500)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func kinds(ev []Event) []string {
	var out []string
	for _, e := range ev {
		out = append(out, e.Kind)
	}
	return out
}

func TestEventsForwardTransitions(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	row := []External{{Proto: "tcp", Port: 80, InternalAddr: "192.168.1.5", InternalPort: 8080}}
	_ = m.recordExternal(ctx, t0, EvidenceUPnP, row)
	if ev := eventsOf(t, m); len(ev) != 1 || ev[0].Kind != EventForwardNew || ev[0].Proto != "tcp" || ev[0].Port != 80 || ev[0].Address != "192.168.1.5" || ev[0].Detail != "192.168.1.5:8080" || !ev[0].At.Equal(t0) || ev[0].Notified {
		t.Fatalf("new: %+v", ev)
	}
	_ = m.recordExternal(ctx, t0.Add(time.Hour), EvidenceUPnP, row) // unveraendert: kein Ereignis
	if ev := eventsOf(t, m); len(ev) != 1 {
		t.Fatalf("a repeated sighting is no event: %v", kinds(ev))
	}
	_ = m.recordExternal(ctx, t0.Add(2*time.Hour), EvidenceUPnP, nil)
	_ = m.recordExternal(ctx, t0.Add(3*time.Hour), EvidenceUPnP, nil) // schon weg: kein zweites "gone"
	_ = m.recordExternal(ctx, t0.Add(4*time.Hour), EvidenceUPnP, row)
	got := kinds(eventsOf(t, m))
	want := []string{EventForwardNew, EventForwardGone, EventForwardNew} // neueste zuerst
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("sequence: %v, want %v", got, want)
	}
	if gone := eventsOf(t, m)[1]; gone.Address != "192.168.1.5" || gone.Detail != "192.168.1.5:8080" {
		t.Fatalf("gone event keeps the target: %+v", gone)
	}
	// ein anderes Ziel fuer denselben Port ist kein Ereignis
	_ = m.recordExternal(ctx, t0.Add(5*time.Hour), EvidenceUPnP, []External{{Proto: "tcp", Port: 80, InternalAddr: "192.168.1.9", InternalPort: 80}})
	if n := len(eventsOf(t, m)); n != 3 {
		t.Fatalf("a changed target is not an event: %d", n)
	}
}

// Review Focus 1: der erste Lesevorgang einer Adresse ist die Baseline und erzeugt keine Ereignisse.
func TestEventsListenBaseline(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	if err := m.recordSelf(ctx, t0, []Listen{selfRow("tcp", 8080), selfRow("tcp", 5432)}); err != nil {
		t.Fatal(err)
	}
	if ev := eventsOf(t, m); len(ev) != 0 {
		t.Fatalf("the first read of the node is the baseline, got %v", kinds(ev))
	}
	_ = m.recordSelf(ctx, t0.Add(5*time.Minute), []Listen{selfRow("tcp", 8080), selfRow("tcp", 5432), selfRow("tcp", 9000)})
	if ev := eventsOf(t, m); len(ev) != 1 || ev[0].Kind != EventListenNew || ev[0].Port != 9000 || ev[0].Address != SelfAddress {
		t.Fatalf("a new port after the baseline: %+v", ev)
	}
	_ = m.recordSelf(ctx, t0.Add(10*time.Minute), []Listen{selfRow("tcp", 8080), selfRow("tcp", 9000)})
	if got := kinds(eventsOf(t, m)); got[0] != EventListenGone || eventsOf(t, m)[0].Port != 5432 {
		t.Fatalf("a vanished port: %v", got)
	}
	// ein Port kommt wieder: neu, nicht Baseline
	_ = m.recordSelf(ctx, t0.Add(15*time.Minute), []Listen{selfRow("tcp", 8080), selfRow("tcp", 9000), selfRow("tcp", 5432)})
	if ev := eventsOf(t, m); ev[0].Kind != EventListenNew || ev[0].Port != 5432 {
		t.Fatalf("a reopened port is new: %+v", ev[0])
	}
}

func TestEventsHostBaselineIsPerAddress(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	a, b := netip.MustParseAddr("192.168.1.20"), netip.MustParseAddr("192.168.1.21")
	_ = m.recordHost(ctx, t0, a, []PortResult{{22, StateOpen}, {80, StateOpen}})
	if len(eventsOf(t, m)) != 0 {
		t.Fatal("first scan of a device: baseline")
	}
	_ = m.recordHost(ctx, t0.Add(time.Hour), b, []PortResult{{443, StateOpen}}) // anderes Geraet: eigene Baseline
	if len(eventsOf(t, m)) != 0 {
		t.Fatal("first scan of another device: baseline again")
	}
	_ = m.recordHost(ctx, t0.Add(2*time.Hour), a, []PortResult{{22, StateOpen}, {80, StateClosed}, {8080, StateOpen}})
	got := kinds(eventsOf(t, m))
	if len(got) != 2 {
		t.Fatalf("one new port and one gone port: %v", got)
	}
	seen := map[string]bool{got[0]: true, got[1]: true}
	if !seen[EventListenNew] || !seen[EventListenGone] {
		t.Fatalf("events: %v", got)
	}
}

func TestEventsTruncatedListNoGone(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	_ = m.recordExternal(ctx, t0, EvidenceUPnP, []External{{Proto: "tcp", Port: 22, InternalAddr: "192.168.1.5", InternalPort: 22}})
	if err := m.recordExternalMode(ctx, t0.Add(time.Hour), EvidenceUPnP, nil, false); err != nil {
		t.Fatal(err)
	}
	if ev := eventsOf(t, m); len(ev) != 1 || ev[0].Kind != EventForwardNew {
		t.Fatalf("a truncated list creates no gone event: %v", kinds(ev))
	}
}

func TestEventsOrderAndLimit(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	var rows []External // wachsende Liste: nur neue Weiterleitungen, keine weggefallenen
	for i := 0; i < 60; i++ {
		rows = append(rows, External{Proto: "tcp", Port: 1000 + i, InternalAddr: "192.168.1.5", InternalPort: 80})
		_ = m.recordExternal(ctx, t0.Add(time.Duration(i)*time.Hour), EvidenceUPnP, rows)
	}
	ev, err := m.Events(ctx, 0)
	if err != nil || len(ev) != 50 || ev[0].Port != 1059 || ev[49].Port != 1010 {
		t.Fatalf("limit 0 means 50, newest first: %d %v", len(ev), err)
	}
	if ev, _ := m.Events(ctx, 3); len(ev) != 3 {
		t.Fatalf("limit 3: %d", len(ev))
	}
	if ev, _ := m.Events(ctx, 1000); len(ev) != 60 {
		t.Fatalf("limit 1000 is clamped to 500 and returns all 60: %d", len(ev))
	}
	if ev, _ := m.Events(ctx, -5); len(ev) != 50 {
		t.Fatalf("a negative limit means 50: %d", len(ev))
	}
}

func TestCleanupEvents(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	_ = m.recordExternal(ctx, t0, EvidenceUPnP, []External{{Proto: "tcp", Port: 80, InternalAddr: "192.168.1.5", InternalPort: 80}})
	_ = m.recordExternal(ctx, t0.Add(40*24*time.Hour), EvidenceUPnP, []External{{Proto: "tcp", Port: 80, InternalAddr: "192.168.1.5", InternalPort: 80}, {Proto: "tcp", Port: 81, InternalAddr: "192.168.1.5", InternalPort: 81}})
	if err := m.saveRaw(ctx, Settings{IntervalHours: 24, KeepDays: 30}); err != nil {
		t.Fatal(err)
	}
	n, err := m.CleanupEvents(ctx, t0.Add(41*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("cleanup removed %d (%v), want 1", n, err)
	}
	if ev := eventsOf(t, m); len(ev) != 1 || ev[0].Port != 81 {
		t.Fatalf("the young event stays: %+v", ev)
	}
	_ = m.saveRaw(ctx, Settings{IntervalHours: 24, KeepDays: 0}) // unbegrenzt
	if n, err := m.CleanupEvents(ctx, t0.Add(4000*24*time.Hour)); err != nil || n != 0 {
		t.Fatalf("keep_days 0 keeps everything: %d %v", n, err)
	}
}

func TestSaveSettingsKeepDays(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	if got := m.LoadSettings(ctx); got.KeepDays != 90 {
		t.Fatalf("default: %d", got.KeepDays)
	}
	if err := m.SaveSettings(ctx, Settings{IntervalHours: 24, KeepDays: 7}); !errors.Is(err, ErrInvalidKeepDays) {
		t.Fatalf("7 days: %v", err)
	}
	for _, d := range KeepDaysOptions {
		if err := m.SaveSettings(ctx, Settings{IntervalHours: 24, KeepDays: d}); err != nil {
			t.Fatalf("%d: %v", d, err)
		}
		if got := m.LoadSettings(ctx); got.KeepDays != d {
			t.Fatalf("round trip %d: %d", d, got.KeepDays)
		}
	}
}

// Review (final): ein Geraet ohne offene Ports hat trotzdem eine Baseline; sein erster offener Port ist ein Ereignis.
func TestEventsHostWithoutOpenPortsStillGetsBaseline(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.168.1.30")
	// erreichbar (ein Port zu), aber nichts offen: das ist die Baseline
	if err := m.recordHost(ctx, t0, ip, []PortResult{{22, StateClosed}, {80, StateClosed}, {443, StateFiltered}}); err != nil {
		t.Fatal(err)
	}
	if err := m.recordHost(ctx, t0.Add(24*time.Hour), ip, []PortResult{{22, StateOpen}, {80, StateClosed}}); err != nil {
		t.Fatal(err)
	}
	got := eventsOf(t, m)
	if len(got) != 1 || got[0].Kind != EventListenNew || got[0].Port != 22 || got[0].Address != "192.168.1.30" {
		t.Fatalf("the first open port of a known quiet device is an event: %+v", got)
	}
	// Forget setzt die Baseline zurueck
	_ = m.Forget(ctx, "192.168.1.30")
	_ = m.recordHost(ctx, t0.Add(48*time.Hour), ip, []PortResult{{22, StateOpen}})
	if n := len(eventsOf(t, m)); n != 1 {
		t.Fatalf("after Forget the next scan is a baseline again: %d events", n)
	}
}
