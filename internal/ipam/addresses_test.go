package ipam

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAddressesSortedNumerically(t *testing.T) {
	m, v4, _ := ingestEnv(t)
	ctx := context.Background()
	_, _ = m.Ingest(ctx, t0, []Observation{obs("192.168.1.100", "", "", SourceNeighbor), obs("192.168.1.2", "", "", SourceNeighbor), obs("192.168.1.10", "", "", SourceNeighbor)})
	list, err := m.Addresses(ctx, v4.ID)
	if err != nil || len(list) != 3 {
		t.Fatalf("list: %d %v", len(list), err)
	}
	if list[0].IP.String() != "192.168.1.2" || list[1].IP.String() != "192.168.1.10" || list[2].IP.String() != "192.168.1.100" {
		t.Fatalf("order: %v %v %v", list[0].IP, list[1].IP, list[2].IP)
	}
}

func TestAddAddressManual(t *testing.T) {
	m, v4, _ := ingestEnv(t)
	ctx := context.Background()
	if _, err := m.AddAddress(ctx, 999, "192.168.1.5", AddressEdit{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown subnet: %v", err)
	}
	if _, err := m.AddAddress(ctx, v4.ID, "10.0.0.5", AddressEdit{}); !errors.Is(err, ErrOutsideSubnet) {
		t.Errorf("outside: %v", err)
	}
	if _, err := m.AddAddress(ctx, v4.ID, "nonsense", AddressEdit{}); !errors.Is(err, ErrInvalidIP) {
		t.Errorf("invalid ip: %v", err)
	}
	if _, err := m.AddAddress(ctx, v4.ID, "192.168.1.5", AddressEdit{ReservedMAC: "xyz"}); !errors.Is(err, ErrInvalidMAC) {
		t.Errorf("mac: %v", err)
	}
	if _, err := m.AddAddress(ctx, v4.ID, "192.168.1.5", AddressEdit{Name: strings.Repeat("a", 254)}); !errors.Is(err, ErrInvalidLabel) {
		t.Errorf("label: %v", err)
	}
	a, err := m.AddAddress(ctx, v4.ID, "192.168.1.5", AddressEdit{Name: " Drucker ", Note: "Flur", Reserved: true, ReservedMAC: "AA-BB-CC-00-00-05"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == 0 || a.Name != "Drucker" || a.ReservedMAC != "aa:bb:cc:00:00:05" || !a.Reserved || !a.Acknowledged || a.LastSource != SourceManual || !a.LastSeen.IsZero() {
		t.Fatalf("added: %+v", a)
	}
	if _, err := m.AddAddress(ctx, v4.ID, "192.168.1.5", AddressEdit{}); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate: %v", err)
	}
	// IPv4-in-IPv6 gilt als IPv4 und ist dann ebenfalls doppelt
	if _, err := m.AddAddress(ctx, v4.ID, "::ffff:192.168.1.5", AddressEdit{}); !errors.Is(err, ErrExists) {
		t.Errorf("mapped duplicate: %v", err)
	}
}

func TestUpdateAddress(t *testing.T) {
	m, v4, _ := ingestEnv(t)
	ctx := context.Background()
	_, _ = m.Ingest(ctx, t0, []Observation{obs("192.168.1.7", "aa:bb:cc:00:00:07", "quelle", SourceDNS64)})
	id := addrOf(t, m, v4, "192.168.1.7").ID
	a, err := m.UpdateAddress(ctx, id, AddressEdit{Name: "NAS", Note: "Keller", Reserved: true, ReservedMAC: "aa:bb:cc:00:00:07"})
	if err != nil || a.Name != "NAS" || a.Note != "Keller" || !a.Reserved || !a.Acknowledged || a.SourceName != "quelle" {
		t.Fatalf("update: %+v %v", a, err)
	}
	a, err = m.UpdateAddress(ctx, id, AddressEdit{}) // leer erlaubt: Reservierung und MAC weg
	if err != nil || a.Name != "" || a.Reserved || a.ReservedMAC != "" {
		t.Fatalf("clear: %+v %v", a, err)
	}
	if _, err := m.UpdateAddress(ctx, 999, AddressEdit{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
	if _, err := m.UpdateAddress(ctx, id, AddressEdit{ReservedMAC: "zz"}); !errors.Is(err, ErrInvalidMAC) {
		t.Errorf("bad mac: %v", err)
	}
}

func TestAcknowledgeAndIgnore(t *testing.T) {
	m, v4, _ := ingestEnv(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = m.Ingest(ctx, now, []Observation{obs("192.168.1.8", "", "x", SourceDNS64)}) // Baseline
	_, _ = m.Ingest(ctx, now, []Observation{obs("192.168.1.9", "", "", SourceNeighbor), obs("192.168.1.10", "", "", SourceNeighbor)})
	a, b := addrOf(t, m, v4, "192.168.1.9"), addrOf(t, m, v4, "192.168.1.10")
	if a.StatusAt(now) != StatusNew || b.StatusAt(now) != StatusNew {
		t.Fatalf("both must be new: %s %s", a.StatusAt(now), b.StatusAt(now))
	}
	if err := m.Acknowledge(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.SetIgnored(ctx, b.ID, true); err != nil {
		t.Fatal(err)
	}
	if s := addrOf(t, m, v4, "192.168.1.9").StatusAt(now); s != StatusUsed {
		t.Errorf("acknowledged: %s", s)
	}
	if s := addrOf(t, m, v4, "192.168.1.10").StatusAt(now); s != StatusUsed {
		t.Errorf("ignored: %s", s)
	}
	if err := m.Acknowledge(ctx, 999); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
	if err := m.DeleteAddress(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteAddress(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

func TestAcknowledgeAll(t *testing.T) {
	m, v4, v6 := ingestEnv(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = m.Ingest(ctx, now, []Observation{obs("192.168.1.8", "", "", SourceNeighbor), obs("fd00:64::8", "", "", SourceNeighbor)}) // Baseline: beide neu
	_, _ = m.Ingest(ctx, now, []Observation{obs("192.168.1.9", "", "", SourceNeighbor), obs("192.168.1.11", "", "named", SourceDNS64)})
	n, err := m.acknowledgeAll(ctx, v4.ID, now)
	if err != nil || n != 2 { // .8 und .9; .11 hat einen Namen, das IPv6-Netz bleibt unberuehrt
		t.Fatalf("acknowledged %d %v, want 2", n, err)
	}
	if s := addrOf(t, m, v6, "fd00:64::8").StatusAt(now); s != StatusNew {
		t.Errorf("other subnet untouched: %s", s)
	}
	if n, _ := m.acknowledgeAll(ctx, v4.ID, now); n != 0 {
		t.Errorf("second run: %d", n)
	}
}

func TestStats(t *testing.T) {
	m, v4, v6 := ingestEnv(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = m.Ingest(ctx, now, []Observation{obs("192.168.1.1", "aa:bb:cc:00:00:01", "router", SourceDNS64)}) // Baseline
	_, _ = m.Ingest(ctx, now, []Observation{obs("192.168.1.2", "", "", SourceNeighbor), obs("192.168.1.3", "aa:bb:cc:00:00:03", "pc", SourceDNS64)})
	// Reservierung ohne Gerat und Reservierung mit Konflikt
	if _, err := m.AddAddress(ctx, v4.ID, "192.168.1.200", AddressEdit{Reserved: true}); err != nil {
		t.Fatal(err)
	}
	c, _ := m.AddAddress(ctx, v4.ID, "192.168.1.201", AddressEdit{Reserved: true, ReservedMAC: "aa:bb:cc:00:00:99"})
	_, _ = m.Ingest(ctx, now, []Observation{obs("192.168.1.201", "aa:bb:cc:00:00:55", "", SourceNeighbor)})
	_, _ = m.Ingest(ctx, now, []Observation{obs("fd00:64::1", "", "", SourceNeighbor)})
	_ = c
	st, err := m.Stats(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	s4, s6 := st[v4.ID], st[v6.ID]
	if s4.Size != 254 || s4.Used != 4 || s4.Reserved != 2 || s4.New != 1 || s4.Conflicts != 1 {
		t.Fatalf("v4 stats: %+v", s4)
	}
	if s6.Size != 0 || s6.Used != 1 {
		t.Fatalf("v6 stats: %+v", s6)
	}
}
