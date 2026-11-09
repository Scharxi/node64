package exposure

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/netstat"
)

// fastScan: Pausen weg, kurze Zeitlimits; stellt die Paketvariablen nach dem Test zurueck.
func fastScan(t *testing.T) {
	t.Helper()
	oldPause, oldOpts, oldSelf := scanPause, newScanOptions, selfEvery
	scanPause = 0
	newScanOptions = func() ScanOptions { o := DefaultScanOptions(); o.Timeout = 50 * time.Millisecond; return o }
	t.Cleanup(func() { scanPause, newScanOptions, selfEvery = oldPause, oldOpts, oldSelf })
}

func fakeIPAM(m *Module, subnets []SubnetRef, hosts map[int64][]HostRef) {
	m.SetSubnets(func(context.Context) ([]SubnetRef, error) { return subnets, nil })
	m.SetHosts(func(_ context.Context, id int64) ([]HostRef, error) { return hosts[id], nil })
}

func TestSettingsRoundTripAndValidation(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	fakeIPAM(m, []SubnetRef{{ID: 1, Name: "Heim", CIDR: netip.MustParsePrefix("192.168.1.0/24")}, {ID: 2, Name: "Gaeste", CIDR: netip.MustParsePrefix("192.168.2.0/24")}}, nil)
	if got := m.LoadSettings(ctx); got.IntervalHours != 24 || len(got.Ports) != 0 || len(got.Subnets) != 0 {
		t.Fatalf("defaults: %+v", got)
	}
	if err := m.SaveSettings(ctx, Settings{IntervalHours: 7}); !errors.Is(err, ErrInvalidInterval) {
		t.Errorf("interval 7: %v", err)
	}
	var many []int
	for p := 40000; p < 40100; p++ {
		many = append(many, p)
	}
	if err := m.SaveSettings(ctx, Settings{IntervalHours: 24, Ports: many}); !errors.Is(err, ErrTooManyPorts) {
		t.Errorf("100 ports: %v", err)
	}
	if err := m.SaveSettings(ctx, Settings{IntervalHours: 24, Ports: []int{0}}); !errors.Is(err, ErrInvalidPorts) {
		t.Errorf("port 0: %v", err)
	}
	if err := m.SaveSettings(ctx, Settings{IntervalHours: 24, Subnets: []int64{99}}); !errors.Is(err, ErrUnknownSubnet) {
		t.Errorf("unknown subnet: %v", err)
	}
	if err := m.SaveSettings(ctx, Settings{IntervalHours: 6, Ports: []int{40001, 40001, 40002}, Subnets: []int64{2, 1, 2}}); err != nil {
		t.Fatal(err)
	}
	got := m.LoadSettings(ctx)
	if got.IntervalHours != 6 || len(got.Ports) != 2 || got.Ports[0] != 40001 || len(got.Subnets) != 2 || got.Subnets[0] != 1 || got.Subnets[1] != 2 {
		t.Fatalf("round trip: %+v", got)
	}
}

func TestScanSubnetsRecordsOpenPorts(t *testing.T) {
	fastScan(t)
	m := newTestModule(t)
	ctx := context.Background()
	_, port := listenTCP(t)
	fakeIPAM(m, []SubnetRef{{ID: 1, Name: "Lokal", CIDR: netip.MustParsePrefix("127.0.0.0/8")}},
		map[int64][]HostRef{1: {{IP: netip.MustParseAddr("127.0.0.1"), Name: "dieser rechner"}}})
	if err := m.SaveSettings(ctx, Settings{IntervalHours: 24, Ports: []int{port}, Subnets: []int64{1}}); err != nil {
		t.Fatal(err)
	}
	if err := m.scanSubnets(ctx, t0); err != nil {
		t.Fatal(err)
	}
	if s := stateOf(t, m, "127.0.0.1", "tcp", port); s.State != "open" || s.Source != "scan" {
		t.Fatalf("scanned port: %+v", s)
	}
	if st := m.Status(); st.Hosts != 1 || !st.LastScanAt.Equal(t0) || st.LastErr != "" {
		t.Fatalf("status: %+v", st)
	}
}

func TestScanSkipsWhenIPAMUnavailable(t *testing.T) {
	fastScan(t)
	m := newTestModule(t)
	ctx := context.Background()
	m.SetSubnets(func(context.Context) ([]SubnetRef, error) { return nil, errors.New("ipam off") })
	m.SetHosts(func(context.Context, int64) ([]HostRef, error) { return nil, errors.New("ipam off") })
	if err := m.saveRaw(ctx, Settings{IntervalHours: 24, Subnets: []int64{1}}); err != nil {
		t.Fatal(err)
	}
	if err := m.scanSubnets(ctx, t0); err != nil {
		t.Fatalf("unavailable IPAM must not be an error: %v", err)
	}
	if rows, _ := m.Listening(ctx, ""); len(rows) != 0 {
		t.Fatalf("nothing may be stored: %+v", rows)
	}
	if got := m.LoadSettings(ctx); len(got.Subnets) != 1 {
		t.Fatalf("the subnet choice must survive an IPAM outage: %+v", got)
	}
}

func TestScanPrunesSubnetsThatAreGone(t *testing.T) {
	fastScan(t)
	m := newTestModule(t)
	ctx := context.Background()
	fakeIPAM(m, []SubnetRef{{ID: 1, Name: "Heim", CIDR: netip.MustParsePrefix("192.168.1.0/24")}}, nil)
	_ = m.saveRaw(ctx, Settings{IntervalHours: 24, Subnets: []int64{1, 7}})
	if err := m.scanSubnets(ctx, t0); err != nil {
		t.Fatal(err)
	}
	if got := m.LoadSettings(ctx); len(got.Subnets) != 1 || got.Subnets[0] != 1 {
		t.Fatalf("subnet 7 no longer exists in IPAM and must be dropped: %+v", got)
	}
}

// Review Focus 2: ein Geraet, das nicht antwortet, behaelt seine Ports.
func TestScanOfflineHostKeepsPorts(t *testing.T) {
	fastScan(t)
	m := newTestModule(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.168.1.30")
	_ = m.recordHost(ctx, t0, ip, []PortResult{{22, StateOpen}})
	newScanOptions = func() ScanOptions {
		o := DefaultScanOptions()
		o.Timeout = 20 * time.Millisecond
		o.Dial = func(c context.Context, _, _ string) (net.Conn, error) { <-c.Done(); return nil, c.Err() }
		return o
	}
	fakeIPAM(m, []SubnetRef{{ID: 1, Name: "Heim", CIDR: netip.MustParsePrefix("192.168.1.0/24")}}, map[int64][]HostRef{1: {{IP: ip}}})
	_ = m.saveRaw(ctx, Settings{IntervalHours: 24, Ports: []int{22}, Subnets: []int64{1}})
	if err := m.scanSubnets(ctx, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if s := stateOf(t, m, "192.168.1.30", "tcp", 22); s.State != "open" {
		t.Fatalf("offline host must keep its ports: %+v", s)
	}
}

// Review Focus 5: zwei Laeufe gleichzeitig werden serialisiert.
func TestRunNowBusy(t *testing.T) {
	fastScan(t)
	m := newTestModule(t)
	ctx := context.Background()
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	m.SetSubnets(func(context.Context) ([]SubnetRef, error) {
		return []SubnetRef{{ID: 1, Name: "Heim", CIDR: netip.MustParsePrefix("192.168.1.0/24")}}, nil
	})
	m.SetHosts(func(context.Context, int64) ([]HostRef, error) {
		entered <- struct{}{}
		<-release
		return nil, nil
	})
	_ = m.saveRaw(ctx, Settings{IntervalHours: 24, Subnets: []int64{1}})
	m.SetListeners(func() ([]netstat.Listener, bool) { return nil, true })
	done := make(chan error, 1)
	go func() { done <- m.RunNow(ctx) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first run did not start")
	}
	if !m.Status().Running {
		t.Fatal("status must show the running scan")
	}
	if err := m.RunNow(ctx); !errors.Is(err, ErrBusy) {
		t.Fatalf("second run: %v, want ErrBusy", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first run: %v", err)
	}
	if m.Status().Running {
		t.Fatal("still running after the run ended")
	}
}

func TestStartReadsSelfAndStops(t *testing.T) {
	fastScan(t)
	selfEvery = 10 * time.Millisecond
	m := newTestModule(t)
	var calls atomic.Int64
	m.SetListeners(func() ([]netstat.Listener, bool) {
		calls.Add(1)
		return []netstat.Listener{{Proto: "tcp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 8080}}, true
	})
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if calls.Load() < 3 {
		t.Fatalf("self read %d times, want at least 3", calls.Load())
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := calls.Load()
	time.Sleep(60 * time.Millisecond)
	if calls.Load() != after {
		t.Fatalf("polling continued after Stop: %d -> %d", after, calls.Load())
	}
	if s := stateOf(t, m, SelfAddress, "tcp", 8080); s.State != "open" {
		t.Fatalf("self row: %+v", s)
	}
}

func TestScanDoesNotRunWithoutEnabledSubnet(t *testing.T) {
	fastScan(t)
	m := newTestModule(t)
	var asked atomic.Int64
	m.SetSubnets(func(context.Context) ([]SubnetRef, error) { asked.Add(1); return nil, nil })
	m.SetHosts(func(context.Context, int64) ([]HostRef, error) { asked.Add(1); return nil, nil })
	if m.scanDue(context.Background(), t0) {
		t.Fatal("no subnet enabled: no scan due")
	}
	if err := m.scanSubnets(context.Background(), t0); err != nil || asked.Load() != 0 {
		t.Fatalf("nothing may be asked: %v asked=%d", err, asked.Load())
	}
}

func TestScanDueFollowsInterval(t *testing.T) {
	fastScan(t)
	m := newTestModule(t)
	ctx := context.Background()
	fakeIPAM(m, []SubnetRef{{ID: 1, Name: "Heim", CIDR: netip.MustParsePrefix("192.168.1.0/24")}}, nil)
	_ = m.saveRaw(ctx, Settings{IntervalHours: 6, Subnets: []int64{1}})
	if !m.scanDue(ctx, t0) {
		t.Fatal("never scanned: due")
	}
	_ = m.scanSubnets(ctx, t0)
	if m.scanDue(ctx, t0.Add(5*time.Hour)) {
		t.Fatal("5h after a 6h interval: not due")
	}
	if !m.scanDue(ctx, t0.Add(6*time.Hour)) {
		t.Fatal("6h: due")
	}
}

// markScanned setzt "gerade gescannt", damit die Schleife von allein keinen Scan startet.
func markScanned(t *testing.T, m *Module) {
	t.Helper()
	if err := m.core.SetSetting(context.Background(), setLastScan, "2099-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
}

func TestSaveSettingsRejectsNonPrivateSubnets(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	fakeIPAM(m, []SubnetRef{
		{ID: 1, Name: "LAN", CIDR: netip.MustParsePrefix("192.168.1.0/24")},
		{ID: 2, Name: "ULA", CIDR: netip.MustParsePrefix("fd00:64::/64")},
		{ID: 3, Name: "GUA", CIDR: netip.MustParsePrefix("2001:db8::/64")},
		{ID: 4, Name: "Oeffentlich", CIDR: netip.MustParsePrefix("8.8.8.0/24")},
	}, nil)
	if err := m.SaveSettings(ctx, Settings{IntervalHours: 24, Subnets: []int64{1, 2}}); err != nil {
		t.Fatalf("private subnets: %v", err)
	}
	for _, id := range []int64{3, 4} {
		if err := m.SaveSettings(ctx, Settings{IntervalHours: 24, Subnets: []int64{id}}); !errors.Is(err, ErrSubnetNotPrivate) {
			t.Errorf("subnet %d: %v, want ErrSubnetNotPrivate", id, err)
		}
	}
}

// Nach Stop laufen keine Goroutines mehr: auch ein Lauf aus "Jetzt pruefen" ist beendet.
func TestStopWaitsForRun(t *testing.T) {
	fastScan(t)
	m := newTestModule(t)
	ctx := context.Background()
	markScanned(t, m)
	fakeIPAM(m, []SubnetRef{{ID: 1, Name: "Lokal", CIDR: netip.MustParsePrefix("127.0.0.0/8")}},
		map[int64][]HostRef{1: {{IP: netip.MustParseAddr("127.0.0.1")}}})
	if err := m.SaveSettings(ctx, Settings{IntervalHours: 24, Subnets: []int64{1}}); err != nil {
		t.Fatal(err)
	}
	newScanOptions = func() ScanOptions {
		o := DefaultScanOptions()
		o.Dial = func(context.Context, string, string) (net.Conn, error) {
			time.Sleep(150 * time.Millisecond)
			return nil, syscall.ECONNREFUSED
		}
		return o
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.StartRun(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !m.Status().Running && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !m.Status().Running {
		t.Fatal("run did not start")
	}
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := m.Stop(sctx); err != nil {
		t.Fatal(err)
	}
	if m.Status().Running {
		t.Fatal("a run is still active after Stop returned")
	}
}

// Ein langer LAN-Scan darf das Lesen der Node nicht aufhalten.
func TestTickDoesNotBlockSelfSnapshot(t *testing.T) {
	fastScan(t)
	selfEvery = 10 * time.Millisecond
	m := newTestModule(t)
	ctx := context.Background()
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	var first atomic.Bool
	m.SetSubnets(func(context.Context) ([]SubnetRef, error) {
		return []SubnetRef{{ID: 1, Name: "Heim", CIDR: netip.MustParsePrefix("192.168.1.0/24")}}, nil
	})
	m.SetHosts(func(context.Context, int64) ([]HostRef, error) {
		if first.CompareAndSwap(false, true) {
			entered <- struct{}{}
			<-release
		}
		return nil, nil
	})
	var reads atomic.Int64
	m.SetListeners(func() ([]netstat.Listener, bool) { reads.Add(1); return nil, true })
	if err := m.saveRaw(ctx, Settings{IntervalHours: 24, Subnets: []int64{1}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil { // faellig: der erste Scan startet sofort und haengt
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("scan did not start")
	}
	before := reads.Load()
	time.Sleep(150 * time.Millisecond)
	if got := reads.Load() - before; got < 3 {
		t.Fatalf("the node was read only %d times during a running scan, want at least 3", got)
	}
	close(release)
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

// Zwei Starts hintereinander: der zweite erfaehrt sofort, dass schon ein Lauf aktiv ist.
func TestStartRunSecondIsBusy(t *testing.T) {
	fastScan(t)
	m := newTestModule(t)
	ctx := context.Background()
	markScanned(t, m)
	release := make(chan struct{})
	var first atomic.Bool
	fakeIPAM(m, []SubnetRef{{ID: 1, Name: "Heim", CIDR: netip.MustParsePrefix("192.168.1.0/24")}}, nil)
	m.SetHosts(func(context.Context, int64) ([]HostRef, error) {
		if first.CompareAndSwap(false, true) {
			<-release
		}
		return nil, nil
	})
	_ = m.saveRaw(ctx, Settings{IntervalHours: 24, Subnets: []int64{1}})
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.StartRun(); err != nil {
		t.Fatal(err)
	}
	if err := m.StartRun(); !errors.Is(err, ErrBusy) {
		t.Fatalf("second start: %v, want ErrBusy", err)
	}
	close(release)
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestTickCleansUpEventsHourly(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	m.SetListeners(func() ([]netstat.Listener, bool) { return nil, true })
	if err := m.saveRaw(ctx, Settings{IntervalHours: 24, KeepDays: 30}); err != nil {
		t.Fatal(err)
	}
	var rows []External // wachsende Liste: nur neue Weiterleitungen, keine weggefallenen
	old := func(port int) {
		rows = append(rows, External{Proto: "tcp", Port: port, InternalAddr: "192.168.1.5", InternalPort: 80})
		_ = m.recordExternal(ctx, t0.Add(-100*24*time.Hour), EvidenceUPnP, rows)
	}
	old(80)
	m.tick(ctx, t0)
	if ev := eventsOf(t, m); len(ev) != 0 {
		t.Fatalf("the first tick cleans up: %+v", ev)
	}
	old(81)
	m.tick(ctx, t0.Add(30*time.Minute))
	if ev := eventsOf(t, m); len(ev) != 1 {
		t.Fatalf("within the hour nothing is cleaned up again: %+v", ev)
	}
	m.tick(ctx, t0.Add(61*time.Minute))
	if ev := eventsOf(t, m); len(ev) != 0 {
		t.Fatalf("after the hour it is cleaned up: %+v", ev)
	}
}
