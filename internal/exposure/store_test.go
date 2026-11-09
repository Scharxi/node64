package exposure

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func selfRow(proto string, port int) Listen {
	return Listen{Address: SelfAddress, Proto: proto, Port: port, State: "open", Service: "x", Bind: "all", Owner: "web", Source: "self"}
}

func stateOf(t *testing.T, m *Module, address, proto string, port int) Listen {
	t.Helper()
	rows, err := m.Listening(context.Background(), address)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Proto == proto && r.Port == port {
			return r
		}
	}
	t.Fatalf("row %s %s/%d not found in %+v", address, proto, port, rows)
	return Listen{}
}

func TestRecordSelfAndGone(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	if err := m.recordSelf(ctx, t0, []Listen{selfRow("tcp", 8080), selfRow("tcp", 5432)}); err != nil {
		t.Fatal(err)
	}
	t1 := t0.Add(5 * time.Minute)
	if err := m.recordSelf(ctx, t1, []Listen{selfRow("tcp", 8080)}); err != nil {
		t.Fatal(err)
	}
	a, b := stateOf(t, m, SelfAddress, "tcp", 8080), stateOf(t, m, SelfAddress, "tcp", 5432)
	if a.State != "open" || !a.FirstSeen.Equal(t0) || !a.LastSeen.Equal(t1) || a.Owner != "web" || a.Source != "self" {
		t.Fatalf("still open: %+v", a)
	}
	if b.State != "gone" || !b.LastSeen.Equal(t0) {
		t.Fatalf("gone: %+v", b)
	}
	// wieder offen: first_seen bleibt, state open
	t2 := t1.Add(5 * time.Minute)
	if err := m.recordSelf(ctx, t2, []Listen{selfRow("tcp", 8080), selfRow("tcp", 5432)}); err != nil {
		t.Fatal(err)
	}
	if b = stateOf(t, m, SelfAddress, "tcp", 5432); b.State != "open" || !b.FirstSeen.Equal(t0) || !b.LastSeen.Equal(t2) {
		t.Fatalf("reopened: %+v", b)
	}
}

func TestRecordHostOpenThenClosed(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.168.1.20")
	if err := m.recordHost(ctx, t0, ip, []PortResult{{22, StateOpen}, {80, StateOpen}, {443, StateClosed}}); err != nil {
		t.Fatal(err)
	}
	ssh := stateOf(t, m, "192.168.1.20", "tcp", 22)
	if ssh.State != "open" || ssh.Service != "ssh" || ssh.Source != "scan" || !ssh.FirstSeen.Equal(t0) {
		t.Fatalf("ssh: %+v", ssh)
	}
	t1 := t0.Add(time.Hour)
	if err := m.recordHost(ctx, t1, ip, []PortResult{{22, StateClosed}, {80, StateOpen}}); err != nil {
		t.Fatal(err)
	}
	if s := stateOf(t, m, "192.168.1.20", "tcp", 22); s.State != "gone" {
		t.Fatalf("22 closed now: %+v", s)
	}
	if s := stateOf(t, m, "192.168.1.20", "tcp", 80); s.State != "open" || !s.LastSeen.Equal(t1) || !s.FirstSeen.Equal(t0) {
		t.Fatalf("80: %+v", s)
	}
}

// Review Focus 2: ein Geraet, das gerade aus ist (alles laeuft ins Zeitlimit), behaelt seine bekannten Ports.
func TestRecordHostOfflineKeepsState(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.168.1.21")
	_ = m.recordHost(ctx, t0, ip, []PortResult{{22, StateOpen}, {80, StateOpen}})
	if err := m.recordHost(ctx, t0.Add(time.Hour), ip, []PortResult{{22, StateFiltered}, {80, StateFiltered}}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []int{22, 80} {
		if s := stateOf(t, m, "192.168.1.21", "tcp", p); s.State != "open" || !s.LastSeen.Equal(t0) {
			t.Fatalf("port %d must be untouched while the host is offline: %+v", p, s)
		}
	}
}

func TestRecordHostUnscannedPortKept(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.168.1.22")
	_ = m.recordHost(ctx, t0, ip, []PortResult{{22, StateOpen}, {9999, StateOpen}})
	// der Nutzer hat 9999 aus der Liste genommen: nicht mehr gescannt, also keine Aussage
	if err := m.recordHost(ctx, t0.Add(time.Hour), ip, []PortResult{{22, StateOpen}}); err != nil {
		t.Fatal(err)
	}
	if s := stateOf(t, m, "192.168.1.22", "tcp", 9999); s.State != "open" {
		t.Fatalf("unscanned port must stay as it was: %+v", s)
	}
}

func TestListeningOrderAndForget(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	_ = m.recordSelf(ctx, t0, []Listen{selfRow("tcp", 8080)})
	_ = m.recordHost(ctx, t0, netip.MustParseAddr("192.168.1.10"), []PortResult{{443, StateOpen}, {22, StateOpen}})
	_ = m.recordHost(ctx, t0, netip.MustParseAddr("192.168.1.2"), []PortResult{{80, StateOpen}})
	all, err := m.Listening(ctx, "")
	if err != nil || len(all) != 4 {
		t.Fatalf("all: %d %v", len(all), err)
	}
	want := []struct {
		addr string
		port int
	}{{SelfAddress, 8080}, {"192.168.1.2", 80}, {"192.168.1.10", 22}, {"192.168.1.10", 443}}
	for i, w := range want {
		if all[i].Address != w.addr || all[i].Port != w.port {
			t.Fatalf("order at %d: %+v, want %v", i, all[i], w)
		}
	}
	one, _ := m.Listening(ctx, "192.168.1.10")
	if len(one) != 2 || one[0].Port != 22 {
		t.Fatalf("filter: %+v", one)
	}
	if err := m.Forget(ctx, "192.168.1.10"); err != nil {
		t.Fatal(err)
	}
	if rest, _ := m.Listening(ctx, ""); len(rest) != 2 {
		t.Fatalf("after forget: %+v", rest)
	}
}
