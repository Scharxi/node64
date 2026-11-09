package web

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/exposure"
	"github.com/ipv64net/node64/internal/netstat"
	"github.com/ipv64net/node64/internal/ports"
)

// newExposureApp: Web-Server mit eingeschaltetem Exposure-Modul, angemeldetem Benutzer und Fakes (Sockets, Claims, IPAM).
// setup (optional) ersetzt Fakes vor dem Start des Moduls.
func newExposureApp(t *testing.T, listeners []netstat.Listener, procOK bool, claims []ports.Claim, setup func(*exposure.Module)) (*testApp, *exposure.Module) {
	t.Helper()
	var m *exposure.Module
	a := newTestAppDeps(t, func(d *Deps) {
		m = exposure.New(d.Store, d.Log.Slog(), "test")
		m.SetListeners(func() ([]netstat.Listener, bool) { return listeners, procOK })
		m.SetClaims(func(context.Context) []ports.Claim { return claims })
		m.SetSubnets(func(context.Context) ([]exposure.SubnetRef, error) {
			return []exposure.SubnetRef{{ID: 1, Name: "Heim", CIDR: netip.MustParsePrefix("192.168.1.0/24")}}, nil
		})
		m.SetHosts(func(context.Context, int64) ([]exposure.HostRef, error) { return nil, nil })
		if setup != nil {
			setup(m)
		}
		d.Modules.Register(m)
	})
	ctx := context.Background()
	_ = a.store.SetModuleEnabled(ctx, exposure.Name, true)
	a.registry.StartEnabled(ctx)
	t.Cleanup(a.registry.StopAll)
	loginAs(t, a, "admin", "sehr geheimes passwort")
	// die Schleife liest die Node sofort: warten, bis das Ergebnis gespeichert ist
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st := m.Status(); !st.LastSelfAt.IsZero() {
			if rows, _ := m.Listening(ctx, exposure.SelfAddress); len(rows) > 0 || !st.SelfKnown {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return a, m
}

func exposureCSRF(t *testing.T, a *testApp) string {
	t.Helper()
	_, body := a.get(t, "/exposure")
	return csrfOf(t, body)
}

var testSockets = []netstat.Listener{
	{Proto: "tcp", Addr: netip.MustParseAddr("::"), Port: 8080},
	{Proto: "tcp", Addr: netip.MustParseAddr("127.0.0.1"), Port: 5432},
}

func TestExposurePageRender(t *testing.T) {
	a, _ := newExposureApp(t, testSockets, true, []ports.Claim{{Owner: "web", Purpose: "HTTP", Proto: ports.TCP, Port: 8080, Active: true}}, nil)
	resp, body := a.get(t, "/exposure")
	if resp.StatusCode != 200 {
		t.Fatalf("page: %d", resp.StatusCode)
	}
	for _, want := range []string{`data-port="8080"`, `data-port="5432"`, "web", "HTTP", "fremdes Programm", "nur lokal", "lauscht"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page misses %q", want)
		}
	}
}

// Review Focus 3: /proc nicht lesbar heisst "unbekannt", nicht "keine Ports offen".
func TestExposurePageUnknownProc(t *testing.T) {
	a, _ := newExposureApp(t, nil, false, nil, nil)
	_, body := a.get(t, "/exposure")
	if !strings.Contains(body, "nicht lesbar") {
		t.Fatal("unknown state must be explained")
	}
	if strings.Contains(body, "Keine offenen Ports") {
		t.Fatal("must not claim there are no open ports")
	}
}

func TestExposureSettingsPost(t *testing.T) {
	a, m := newExposureApp(t, testSockets, true, nil, nil)
	ctx := context.Background()
	csrf := exposureCSRF(t, a)
	resp, _ := a.post(t, "/exposure/settings", url.Values{"_csrf": {csrf}, "interval": {"6"}, "ports": {"40001, 40002"}, "subnet": {"1"}})
	if resp.StatusCode != 303 {
		t.Fatalf("valid: %d", resp.StatusCode)
	}
	s := m.LoadSettings(ctx)
	if s.IntervalHours != 6 || len(s.Ports) != 2 || len(s.Subnets) != 1 || s.Subnets[0] != 1 {
		t.Fatalf("saved: %+v", s)
	}
	// ungueltige Ports: Flash, nichts geaendert
	resp, _ = a.post(t, "/exposure/settings", url.Values{"_csrf": {csrf}, "interval": {"24"}, "ports": {"abc"}})
	if resp.StatusCode != 303 {
		t.Fatalf("invalid: %d", resp.StatusCode)
	}
	if _, body := a.get(t, "/exposure"); !strings.Contains(body, "Ungültige Ports") {
		t.Fatal("error flash missing")
	}
	if got := m.LoadSettings(ctx); got.IntervalHours != 6 {
		t.Fatalf("invalid input must not change anything: %+v", got)
	}
	// unbekanntes Subnetz
	a.post(t, "/exposure/settings", url.Values{"_csrf": {csrf}, "interval": {"24"}, "subnet": {"99"}})
	if got := m.LoadSettings(ctx); got.IntervalHours != 6 || len(got.Subnets) != 1 {
		t.Fatalf("unknown subnet must be rejected: %+v", got)
	}
}

func TestExposureScanPostBusy(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	a, m := newExposureApp(t, testSockets, true, nil, func(m *exposure.Module) {
		var first atomic.Bool // nur der erste Aufruf (der Scan) haengt; die Seite fragt die Namen spaeter ohne zu warten
		m.SetHosts(func(context.Context, int64) ([]exposure.HostRef, error) {
			if first.CompareAndSwap(false, true) {
				entered <- struct{}{}
				<-release
			}
			return nil, nil
		})
	})
	ctx := context.Background()
	if err := m.SaveSettings(ctx, exposure.Settings{IntervalHours: 24, Subnets: []int64{1}}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- m.RunNow(ctx) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first run did not start")
	}
	csrf := exposureCSRF(t, a)
	resp, _ := a.post(t, "/exposure/scan", url.Values{"_csrf": {csrf}})
	if resp.StatusCode != 303 {
		t.Fatalf("scan post: %d", resp.StatusCode)
	}
	if _, body := a.get(t, "/exposure"); !strings.Contains(body, "läuft schon") {
		t.Fatal("busy flash missing")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestExposureEscapes(t *testing.T) {
	a, _ := newExposureApp(t, testSockets, true, []ports.Claim{{Owner: "web", Purpose: "<script>x</script>", Proto: ports.TCP, Port: 8080, Active: true}}, nil)
	_, body := a.get(t, "/exposure")
	if strings.Contains(body, "<script>x</script>") || !strings.Contains(body, "&lt;script&gt;x&lt;/script&gt;") {
		t.Fatal("service text must be escaped")
	}
}

func TestExposureGoneWhenDisabled(t *testing.T) {
	a, _ := newExposureApp(t, testSockets, true, nil, nil)
	_ = a.registry.Disable(context.Background(), exposure.Name)
	if resp, _ := a.get(t, "/exposure"); resp.StatusCode != 404 {
		t.Fatalf("disabled module page: %d", resp.StatusCode)
	}
}

// Ein Geraet, das IPAM nicht mehr als gesehen fuehrt, zeigt seine Ports vom letzten Scan, aber als "nicht mehr gesehen".
func TestExposureLANStaleHost(t *testing.T) {
	var present atomic.Bool
	present.Store(true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	a, m := newExposureApp(t, testSockets, true, nil, func(m *exposure.Module) {
		m.SetSubnets(func(context.Context) ([]exposure.SubnetRef, error) {
			return []exposure.SubnetRef{{ID: 1, Name: "Lokal", CIDR: netip.MustParsePrefix("127.0.0.0/8")}}, nil
		})
		m.SetHosts(func(context.Context, int64) ([]exposure.HostRef, error) {
			if present.Load() {
				return []exposure.HostRef{{IP: netip.MustParseAddr("127.0.0.1"), Name: "mein rechner"}}, nil
			}
			return nil, nil
		})
	})
	ctx := context.Background()
	if err := m.SaveSettings(ctx, exposure.Settings{IntervalHours: 24, Ports: []int{port}, Subnets: []int64{1}}); err != nil {
		t.Fatal(err)
	}
	if err := m.RunNow(ctx); err != nil {
		t.Fatal(err)
	}
	_, body := a.get(t, "/exposure")
	if !strings.Contains(body, `data-host="127.0.0.1"`) || !strings.Contains(body, "mein rechner") || strings.Contains(body, "nicht mehr gesehen") {
		t.Fatal("a device IPAM still sees must show up without the stale hint")
	}
	present.Store(false)
	_, body = a.get(t, "/exposure")
	if !strings.Contains(body, `data-host="127.0.0.1"`) || !strings.Contains(body, "nicht mehr gesehen") {
		t.Fatal("a device IPAM no longer sees must be marked as not seen anymore")
	}
}

// Nicht-private Subnetze lassen sich nicht zum Scannen anhaken; die Seite sagt warum.
func TestExposureNonPrivateSubnetIsDisabled(t *testing.T) {
	a, m := newExposureApp(t, testSockets, true, nil, func(m *exposure.Module) {
		m.SetSubnets(func(context.Context) ([]exposure.SubnetRef, error) {
			return []exposure.SubnetRef{{ID: 1, Name: "Heim", CIDR: netip.MustParsePrefix("192.168.1.0/24")},
				{ID: 2, Name: "Global", CIDR: netip.MustParsePrefix("2001:db8::/64")}}, nil
		})
	})
	_, body := a.get(t, "/exposure")
	if !strings.Contains(body, `id="ex-sn-2"`) || !strings.Contains(body, "disabled") || !strings.Contains(body, "kein privates Netz") {
		t.Fatal("the public subnet must be shown as not scannable")
	}
	csrf := csrfOf(t, body)
	a.post(t, "/exposure/settings", url.Values{"_csrf": {csrf}, "interval": {"24"}, "subnet": {"2"}})
	if got := m.LoadSettings(context.Background()); len(got.Subnets) != 0 {
		t.Fatalf("a non-private subnet must be rejected: %+v", got)
	}
}
