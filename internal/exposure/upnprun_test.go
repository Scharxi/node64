package exposure

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/netstat"
)

// upnpModule: Modul mit eingeschaltetem UPnP, das den Fake-Router als Gateway findet.
func upnpModule(t *testing.T, f *fakeIGD) (*Module, *atomic.Int64) {
	t.Helper()
	m := newTestModule(t)
	var asked atomic.Int64
	m.SetGateways(func(context.Context) ([]string, error) { asked.Add(1); return []string{f.url("/desc.xml")}, nil })
	o, _ := testUPnPOptions()
	m.SetUPnPOptions(o)
	m.SetListeners(func() ([]netstat.Listener, bool) { return nil, true })
	if err := m.saveRaw(context.Background(), Settings{IntervalHours: 24, UPnP: true}); err != nil {
		t.Fatal(err)
	}
	return m, &asked
}

func TestReadUPnPRecords(t *testing.T) {
	f := newFakeIGD(t, fakeEntry{80, "TCP", 8080, "192.168.1.5", "1", "Web"}, fakeEntry{51820, "UDP", 51820, "192.168.1.6", "1", "WG"})
	m, _ := upnpModule(t, f)
	ctx := context.Background()
	if err := m.readUPnP(ctx, t0); err != nil {
		t.Fatal(err)
	}
	rows, _ := m.Externals(ctx)
	if len(rows) != 2 || rows[0].Port != 80 || rows[0].InternalAddr != "192.168.1.5" || rows[0].InternalPort != 8080 || rows[0].Evidence != EvidenceUPnP || rows[1].Proto != "udp" {
		t.Fatalf("rows: %+v", rows)
	}
	st := m.Status()
	if !st.UPnPAt.Equal(t0) || st.UPnPErr != "" || st.ExternalIP != "203.0.113.7" || st.Mappings != 2 || st.UPnPTruncated {
		t.Fatalf("status: %+v", st)
	}
}

func TestReadUPnPDisabledDoesNothing(t *testing.T) {
	f := newFakeIGD(t, fakeEntry{80, "TCP", 80, "192.168.1.5", "1", ""})
	m, asked := upnpModule(t, f)
	ctx := context.Background()
	_ = m.saveRaw(ctx, Settings{IntervalHours: 24, UPnP: false})
	if err := m.readUPnP(ctx, t0); err != nil {
		t.Fatal(err)
	}
	if asked.Load() != 0 || f.soapCalls.Load() != 0 {
		t.Fatalf("disabled UPnP must not ask anything: gateways=%d soap=%d", asked.Load(), f.soapCalls.Load())
	}
	if rows, _ := m.Externals(ctx); len(rows) != 0 {
		t.Fatalf("rows: %+v", rows)
	}
}

// Review Focus 3: kein Router gefunden darf nichts auf "weg" setzen.
func TestReadUPnPNoGatewayKeepsRows(t *testing.T) {
	f := newFakeIGD(t, fakeEntry{80, "TCP", 80, "192.168.1.5", "1", ""})
	m, _ := upnpModule(t, f)
	ctx := context.Background()
	if err := m.readUPnP(ctx, t0); err != nil {
		t.Fatal(err)
	}
	m.SetGateways(func(context.Context) ([]string, error) { return nil, nil })
	if err := m.readUPnP(ctx, t0.Add(time.Hour)); err != nil {
		t.Fatalf("no gateway is not an error: %v", err)
	}
	if r := extOf(t, m, "tcp", 80); r.State != "open" || !r.LastSeen.Equal(t0) {
		t.Fatalf("row must stay untouched: %+v", r)
	}
	if st := m.Status(); st.UPnPErr != "no gateway found" {
		t.Fatalf("the status must say why: %+v", st)
	}
	// SSDP selbst scheitert (z. B. kein Multicast): ebenfalls unberuehrt, mit Grund
	m.SetGateways(func(context.Context) ([]string, error) { return nil, errors.New("no multicast") })
	if err := m.readUPnP(ctx, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r := extOf(t, m, "tcp", 80); r.State != "open" {
		t.Fatalf("row must stay untouched: %+v", r)
	}
	if st := m.Status(); st.UPnPErr == "" || st.UPnPErr == "no gateway found" {
		t.Fatalf("the search error must show: %+v", st)
	}
}

func TestReadUPnPRouterErrorKeepsRows(t *testing.T) {
	f := newFakeIGD(t, fakeEntry{80, "TCP", 80, "192.168.1.5", "1", ""})
	m, _ := upnpModule(t, f)
	ctx := context.Background()
	_ = m.readUPnP(ctx, t0)
	f.entries, f.fault = nil, "501" // der Router kann die Liste nicht mehr liefern
	if err := m.readUPnP(ctx, t0.Add(time.Hour)); err != nil {
		t.Fatalf("a router error is a status, not a failure of the run: %v", err)
	}
	if r := extOf(t, m, "tcp", 80); r.State != "open" {
		t.Fatalf("a router error must never end forwards: %+v", r)
	}
	if st := m.Status(); st.UPnPErr == "" {
		t.Fatal("the error must show")
	}
}

// Review Focus 5: ein Erfolg ohne Weiterleitungen beendet die bekannten.
func TestReadUPnPEmptySuccessMarksGone(t *testing.T) {
	f := newFakeIGD(t, fakeEntry{80, "TCP", 80, "192.168.1.5", "1", ""})
	m, _ := upnpModule(t, f)
	ctx := context.Background()
	_ = m.readUPnP(ctx, t0)
	f.entries = nil
	if err := m.readUPnP(ctx, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r := extOf(t, m, "tcp", 80); r.State != "gone" {
		t.Fatalf("an empty successful list ends the forward: %+v", r)
	}
	if st := m.Status(); st.UPnPErr != "" || st.Mappings != 0 {
		t.Fatalf("status: %+v", st)
	}
}

// Eine abgeschnittene Liste (mehr Weiterleitungen als die Obergrenze) darf nichts auf "weg" setzen.
func TestReadUPnPTruncatedDoesNotMarkGone(t *testing.T) {
	f := newFakeIGD(t)
	f.endless = true
	m, _ := upnpModule(t, f)
	ctx := context.Background()
	o, _ := testUPnPOptions()
	o.MaxMappings = 5
	m.SetUPnPOptions(o)
	_ = m.recordExternal(ctx, t0, EvidenceUPnP, []External{{Proto: "tcp", Port: 22, InternalAddr: "192.168.1.9", InternalPort: 22}})
	if err := m.readUPnP(ctx, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r := extOf(t, m, "tcp", 22); r.State != "open" {
		t.Fatalf("a truncated list says nothing about entries beyond it: %+v", r)
	}
	if rows, _ := m.Externals(ctx); len(rows) != 6 {
		t.Fatalf("5 listed plus the old one: %d", len(rows))
	}
	if st := m.Status(); !st.UPnPTruncated {
		t.Fatalf("status must show the cut: %+v", st)
	}
}

func TestReadUPnPManualURL(t *testing.T) {
	f := newFakeIGD(t, fakeEntry{80, "TCP", 80, "192.168.1.5", "1", ""})
	m, asked := upnpModule(t, f)
	ctx := context.Background()
	_ = m.saveRaw(ctx, Settings{IntervalHours: 24, UPnP: true, UPnPURL: f.url("/desc.xml")})
	if err := m.readUPnP(ctx, t0); err != nil {
		t.Fatal(err)
	}
	if asked.Load() != 0 {
		t.Fatal("with a manual URL the search must not run")
	}
	if rows, _ := m.Externals(ctx); len(rows) != 1 {
		t.Fatalf("rows: %+v", rows)
	}
}

func TestSaveSettingsUPnPURL(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	for _, bad := range []string{"http://8.8.8.8/d.xml", "http://router.lan/d.xml", "ftp://192.168.1.1/d.xml"} {
		if err := m.SaveSettings(ctx, Settings{IntervalHours: 24, UPnP: true, UPnPURL: bad}); !errors.Is(err, ErrUnsafeURL) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if err := m.SaveSettings(ctx, Settings{IntervalHours: 24, UPnP: true, UPnPURL: "http://127.0.0.1:5000/d.xml"}); err != nil {
		t.Fatal(err)
	}
	if got := m.LoadSettings(ctx); !got.UPnP || got.UPnPURL != "http://127.0.0.1:5000/d.xml" {
		t.Fatalf("round trip: %+v", got)
	}
	if err := m.SaveSettings(ctx, Settings{IntervalHours: 24}); err != nil {
		t.Fatal(err)
	}
	if got := m.LoadSettings(ctx); got.UPnP || got.UPnPURL != "" {
		t.Fatalf("off and empty: %+v", got)
	}
}

func TestUPnPDueFollowsInterval(t *testing.T) {
	f := newFakeIGD(t)
	m, _ := upnpModule(t, f)
	ctx := context.Background()
	if !m.upnpDue(ctx, t0) {
		t.Fatal("never asked: due")
	}
	_ = m.readUPnP(ctx, t0)
	if m.upnpDue(ctx, t0.Add(59*time.Minute)) {
		t.Fatal("59 minutes: not due")
	}
	if !m.upnpDue(ctx, t0.Add(time.Hour)) {
		t.Fatal("one hour: due")
	}
	_ = m.saveRaw(ctx, Settings{IntervalHours: 24})
	if m.upnpDue(ctx, t0.Add(48*time.Hour)) {
		t.Fatal("switched off: never due")
	}
}

func TestRunNowIncludesUPnP(t *testing.T) {
	fastScan(t)
	f := newFakeIGD(t, fakeEntry{80, "TCP", 80, "192.168.1.5", "1", ""})
	m, _ := upnpModule(t, f)
	ctx := context.Background()
	_ = m.readUPnP(ctx, t0) // gerade erst gefragt: nicht faellig, "Jetzt pruefen" fragt trotzdem
	f.entries = append(f.entries, fakeEntry{443, "TCP", 443, "192.168.1.5", "1", ""})
	if err := m.RunNow(ctx); err != nil {
		t.Fatal(err)
	}
	if rows, _ := m.Externals(ctx); len(rows) != 2 {
		t.Fatalf("RunNow must ask the router again: %+v", rows)
	}
}

func TestStartQueriesUPnP(t *testing.T) {
	fastScan(t)
	selfEvery = 10 * time.Millisecond
	f := newFakeIGD(t, fakeEntry{80, "TCP", 80, "192.168.1.5", "1", ""})
	m, _ := upnpModule(t, f)
	markScanned(t, m)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rows, _ := m.Externals(context.Background()); len(rows) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rows, _ := m.Externals(context.Background()); len(rows) != 1 {
		t.Fatalf("the loop must ask the router after start: %+v", rows)
	}
	if got := f.soapCalls.Load(); got > 10 {
		t.Fatalf("the router must be asked once per interval, not on every tick: %d SOAP calls", got)
	}
}

var _ = netip.Addr{}

// Review: die Seite muss sagen, welcher Router gefragt wurde, und warnen, wenn mehrere geantwortet haben.
func TestReadUPnPShowsLocationAndGateways(t *testing.T) {
	f := newFakeIGD(t, fakeEntry{80, "TCP", 80, "192.168.1.5", "1", ""})
	m, _ := upnpModule(t, f)
	ctx := context.Background()
	if err := m.readUPnP(ctx, t0); err != nil {
		t.Fatal(err)
	}
	if st := m.Status(); st.UPnPLocation != f.url("/desc.xml") || st.UPnPGateways != 1 {
		t.Fatalf("status: %+v", st)
	}
	// zwei Antworten: der erste Ort, der klappt, wird genommen, die Zahl bleibt sichtbar
	m.SetGateways(func(context.Context) ([]string, error) {
		return []string{"http://127.0.0.1:1/none.xml", f.url("/desc.xml")}, nil
	})
	if err := m.readUPnP(ctx, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if st := m.Status(); st.UPnPLocation != f.url("/desc.xml") || st.UPnPGateways != 2 {
		t.Fatalf("status with two answers: %+v", st)
	}
}
