package ipam

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// ingestEnv: Modul mit einem IPv4- und einem IPv6-Subnetz.
func ingestEnv(t *testing.T) (*Module, Subnet, Subnet) {
	t.Helper()
	m := newTestModule(t)
	return m, mustSubnet(t, m, "Heim", "192.168.1.0/24"), mustSubnet(t, m, "ULA", "fd00:64::/64")
}

func obs(ip, mac, name, src string) Observation {
	return Observation{IP: netip.MustParseAddr(ip), MAC: mac, Name: name, Source: src}
}

func addrOf(t *testing.T, m *Module, s Subnet, ip string) Address {
	t.Helper()
	list, err := loadAddresses(context.Background(), m.core.Reader(), s.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range list {
		if a.IP.String() == ip {
			return a
		}
	}
	t.Fatalf("address %s not found", ip)
	return Address{}
}

func countRows(t *testing.T, m *Module) int {
	t.Helper()
	var n int
	_ = m.core.Reader().QueryRowContext(context.Background(), `SELECT count(*) FROM ipam_addresses`).Scan(&n)
	return n
}

func TestIngestOutsideAndSkips(t *testing.T) {
	m, v4, _ := ingestEnv(t)
	res, err := m.Ingest(context.Background(), t0, []Observation{
		obs("10.9.9.9", "", "", SourceNeighbor),                 // in keinem Subnetz
		obs("fe80::1", "aa:bb:cc:00:00:01", "", SourceNeighbor), // Link-Local: nie speichern, nicht zaehlen
		obs("::ffff:192.168.1.5", "", "", SourceDNS64),          // IPv4-in-IPv6
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outside != 1 {
		t.Fatalf("outside: %d", res.Outside)
	}
	if n := countRows(t, m); n != 1 {
		t.Fatalf("rows: %d", n)
	}
	if a := addrOf(t, m, v4, "192.168.1.5"); a.LastSource != SourceDNS64 {
		t.Fatalf("mapped address: %+v", a)
	}
}

func TestIngestNewRow(t *testing.T) {
	m, v4, _ := ingestEnv(t)
	ctx := context.Background()
	if _, err := m.Ingest(ctx, t0, []Observation{obs("192.168.1.10", "AA:BB:CC:00:00:10", "nas", SourceDNS64), obs("192.168.1.11", "00:00:00:00:00:00", "", SourceNeighbor)}); err != nil {
		t.Fatal(err)
	}
	a := addrOf(t, m, v4, "192.168.1.10")
	if a.MAC != "aa:bb:cc:00:00:10" || a.SourceName != "nas" || a.Name != "" || a.LastSource != SourceDNS64 || !a.FirstSeen.Equal(t0) || !a.LastSeen.Equal(t0) {
		t.Fatalf("new row: %+v", a)
	}
	if b := addrOf(t, m, v4, "192.168.1.11"); b.MAC != "" {
		t.Fatalf("invalid mac must be dropped, row stays: %+v", b)
	}
}

func TestIngestKeepsManualData(t *testing.T) {
	m, v4, _ := ingestEnv(t)
	ctx := context.Background()
	if _, err := m.Ingest(ctx, t0, []Observation{obs("192.168.1.20", "aa:bb:cc:00:00:20", "", SourceNeighbor)}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.core.Writer().ExecContext(ctx, `UPDATE ipam_addresses SET name = 'Drucker', note = 'Flur', reserved = 1 WHERE ip = '192.168.1.20'`); err != nil {
		t.Fatal(err)
	}
	later := t0.Add(time.Hour)
	if _, err := m.Ingest(ctx, later, []Observation{obs("192.168.1.20", "", "quelle", SourceDNS64)}); err != nil {
		t.Fatal(err)
	}
	a := addrOf(t, m, v4, "192.168.1.20")
	if a.Name != "Drucker" || a.Note != "Flur" || !a.Reserved || a.SourceName != "quelle" || a.MAC != "aa:bb:cc:00:00:20" || !a.LastSeen.Equal(later) {
		t.Fatalf("manual data must stay, source fills its own: %+v", a)
	}
	// eine aeltere Sichtung setzt last_seen nicht zurueck
	old := Observation{IP: netip.MustParseAddr("192.168.1.20"), Source: SourceDNS64, Seen: t0.Add(-time.Hour)}
	if _, err := m.Ingest(ctx, later, []Observation{old}); err != nil {
		t.Fatal(err)
	}
	if a := addrOf(t, m, v4, "192.168.1.20"); !a.LastSeen.Equal(later) {
		t.Fatalf("last_seen went back: %v", a.LastSeen)
	}
}

func TestIngestBaseline(t *testing.T) {
	m, _, _ := ingestEnv(t)
	ctx := context.Background()
	res, err := m.Ingest(ctx, t0, []Observation{obs("192.168.1.30", "", "", SourceNeighbor), obs("192.168.1.31", "", "", SourceNeighbor)})
	if err != nil || res.New != 0 {
		t.Fatalf("baseline run: %+v %v", res, err)
	}
	res, err = m.Ingest(ctx, t0.Add(time.Minute), []Observation{obs("192.168.1.32", "", "", SourceNeighbor)})
	if err != nil || res.New != 1 {
		t.Fatalf("second run: %+v %v", res, err)
	}
	subs, _ := m.Subnets(ctx)
	if subs[0].BaselineAt.IsZero() || !subs[1].BaselineAt.IsZero() {
		t.Fatalf("baseline_at must be set only for the seen subnet: %v %v", subs[0].BaselineAt, subs[1].BaselineAt)
	}
}

func TestIngestIPv6SameMAC(t *testing.T) {
	m, _, v6 := ingestEnv(t)
	ctx := context.Background()
	if _, err := m.Ingest(ctx, t0, []Observation{obs("fd00:64::1", "aa:bb:cc:00:01:01", "laptop", SourceDNS64)}); err != nil { // Baseline + benannt
		t.Fatal(err)
	}
	res, err := m.Ingest(ctx, t0.Add(time.Minute), []Observation{obs("fd00:64::dead:beef", "aa:bb:cc:00:01:01", "", SourceNeighbor)})
	if err != nil || res.New != 0 {
		t.Fatalf("same mac: %+v %v", res, err)
	}
	a := addrOf(t, m, v6, "fd00:64::dead:beef")
	if !a.AutoKnown || a.StatusAt(t0.Add(time.Minute)) != StatusUsed {
		t.Fatalf("auto known: %+v", a)
	}
	res, _ = m.Ingest(ctx, t0.Add(2*time.Minute), []Observation{obs("fd00:64::cafe", "aa:bb:cc:00:09:09", "", SourceNeighbor)})
	if res.New != 1 {
		t.Fatalf("unknown mac must be new: %+v", res)
	}
}

func TestIngestNamedBySourceIsNotNew(t *testing.T) {
	m, _, _ := ingestEnv(t)
	ctx := context.Background()
	_, _ = m.Ingest(ctx, t0, []Observation{obs("192.168.1.40", "", "x", SourceDNS64)}) // Baseline
	res, err := m.Ingest(ctx, t0.Add(time.Minute), []Observation{obs("192.168.1.41", "", "tv", SourceDNS64), obs("192.168.1.42", "", "", SourceNeighbor)})
	if err != nil || res.New != 1 {
		t.Fatalf("only the unnamed one is new: %+v %v", res, err)
	}
}

func TestIngestConflict(t *testing.T) {
	m, v4, _ := ingestEnv(t)
	ctx := context.Background()
	_, _ = m.Ingest(ctx, t0, []Observation{obs("192.168.1.50", "aa:bb:cc:00:00:50", "", SourceNeighbor)})
	if _, err := m.core.Writer().ExecContext(ctx, `UPDATE ipam_addresses SET reserved = 1, reserved_mac = 'aa:bb:cc:00:00:99' WHERE ip = '192.168.1.50'`); err != nil {
		t.Fatal(err)
	}
	res, err := m.Ingest(ctx, t0.Add(time.Minute), []Observation{obs("192.168.1.50", "aa:bb:cc:00:00:50", "", SourceNeighbor)})
	if err != nil || res.Conflicts != 1 {
		t.Fatalf("conflict: %+v %v", res, err)
	}
	_ = v4
}

func TestCleanup(t *testing.T) {
	m, v4, v6 := ingestEnv(t)
	ctx := context.Background()
	ins := func(s Subnet, ip, extra string, seen time.Time) {
		t.Helper()
		ls := ""
		if !seen.IsZero() {
			ls = seen.UTC().Format(time.RFC3339Nano)
		}
		q := `INSERT INTO ipam_addresses (subnet_id, ip, last_seen, created_at` + extra + `) VALUES (?, ?, ?, 'x'`
		if extra != "" {
			q += `, 1`
		}
		if _, err := m.core.Writer().ExecContext(ctx, q+`)`, s.ID, ip, ls); err != nil {
			t.Fatal(err)
		}
	}
	ins(v4, "192.168.1.60", "", t0.Add(-91*24*time.Hour))                // weg
	ins(v4, "192.168.1.61", "", t0.Add(-89*24*time.Hour))                // bleibt (jung genug)
	ins(v4, "192.168.1.62", ", reserved", t0.Add(-200*24*time.Hour))     // bleibt (reserviert)
	ins(v4, "192.168.1.63", ", acknowledged", t0.Add(-200*24*time.Hour)) // bleibt
	ins(v4, "192.168.1.64", ", ignored", t0.Add(-200*24*time.Hour))      // bleibt
	ins(v4, "192.168.1.65", "", time.Time{})                             // von Hand, nie gesehen: bleibt
	ins(v6, "fd00:64::1", "", t0.Add(-8*24*time.Hour))                   // weg (IPv6 nach 7 Tagen)
	ins(v6, "fd00:64::2", "", t0.Add(-6*24*time.Hour))                   // bleibt
	if _, err := m.core.Writer().ExecContext(ctx, `UPDATE ipam_addresses SET name = 'x' WHERE ip = '192.168.1.61'`); err != nil {
		t.Fatal(err)
	}
	n, err := m.Cleanup(ctx, t0)
	if err != nil || n != 2 {
		t.Fatalf("cleanup removed %d (%v), want 2", n, err)
	}
	if got := countRows(t, m); got != 6 {
		t.Fatalf("rows left: %d", got)
	}
}

func TestIngestDuringDelete(t *testing.T) {
	m, v4, _ := ingestEnv(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			_, _ = m.Ingest(ctx, t0.Add(time.Duration(i)*time.Second), []Observation{obs("192.168.1.70", "", "", SourceNeighbor)})
		}
	}()
	go func() {
		defer wg.Done()
		_ = m.DeleteSubnet(ctx, v4.ID)
	}()
	wg.Wait()
	var orphans int
	_ = m.core.Reader().QueryRowContext(ctx, `SELECT count(*) FROM ipam_addresses WHERE subnet_id NOT IN (SELECT id FROM ipam_subnets)`).Scan(&orphans)
	if orphans != 0 {
		t.Fatalf("orphaned rows: %d", orphans)
	}
}
