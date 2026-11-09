package web

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
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

// ---- Spur 2: Router per UPnP ----

type fakeMap struct {
	Ext    int
	Proto  string
	Int    int
	Client string
	Desc   string
}

// fakeRouterWeb ist ein kleiner UPnP-Router (Beschreibung und SOAP), dessen Weiterleitungen der Test aendern kann.
type fakeRouterWeb struct {
	srv *httptest.Server
	mu  sync.Mutex
	set []fakeMap
}

func (f *fakeRouterWeb) setMaps(m ...fakeMap) { f.mu.Lock(); f.set = m; f.mu.Unlock() }

func newFakeRouterWeb(t *testing.T, maps ...fakeMap) *fakeRouterWeb {
	t.Helper()
	f := &fakeRouterWeb{set: maps}
	idx := regexp.MustCompile(`<NewPortMappingIndex>(\d+)</NewPortMappingIndex>`)
	mux := http.NewServeMux()
	mux.HandleFunc("/desc.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<?xml version="1.0"?><root><device><deviceList><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl</controlURL></service></serviceList></device></deviceList></device></root>`)
	})
	mux.HandleFunc("/ctl", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		action := r.Header.Get("SOAPAction")
		if strings.HasSuffix(action, `#GetExternalIPAddress"`) {
			fmt.Fprint(w, `<Envelope><Body><R><NewExternalIPAddress>203.0.113.7</NewExternalIPAddress></R></Body></Envelope>`)
			return
		}
		i := 0
		if m := idx.FindSubmatch(body); m != nil {
			i, _ = strconv.Atoi(string(m[1]))
		}
		f.mu.Lock()
		set := f.set
		f.mu.Unlock()
		if i >= len(set) {
			w.WriteHeader(500)
			fmt.Fprint(w, `<Envelope><Body><Fault><detail><UPnPError><errorCode>713</errorCode></UPnPError></detail></Fault></Body></Envelope>`)
			return
		}
		e := set[i]
		fmt.Fprintf(w, `<Envelope><Body><R><NewExternalPort>%d</NewExternalPort><NewProtocol>%s</NewProtocol><NewInternalPort>%d</NewInternalPort><NewInternalClient>%s</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>%s</NewPortMappingDescription></R></Body></Envelope>`,
			e.Ext, e.Proto, e.Int, e.Client, e.Desc)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// newUPnPApp: Exposure-App mit eingeschaltetem UPnP; die Node hat die Adresse 192.168.1.2 und lauscht auf 8080 (Besitzer web).
func newUPnPApp(t *testing.T, f *fakeRouterWeb, gateways []string) (*testApp, *exposure.Module) {
	t.Helper()
	a, m := newExposureApp(t, testSockets, true, []ports.Claim{{Owner: "web", Purpose: "HTTP", Proto: ports.TCP, Port: 8080, Active: true}}, func(m *exposure.Module) {
		m.SetGateways(func(context.Context) ([]string, error) { return gateways, nil })
		m.SetLocalAddrs(func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.168.1.2")} })
	})
	if err := m.SaveSettings(context.Background(), exposure.Settings{IntervalHours: 24, UPnP: true}); err != nil {
		t.Fatal(err)
	}
	return a, m
}

// rowOf liefert die Tabellenzeile mit dem Marker (bis zum Zeilenende) oder "".
func rowOf(body, marker string) string {
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	if j := strings.Index(body[i:], "</tr>"); j >= 0 {
		return body[i : i+j]
	}
	return body[i:]
}

func TestExposureReachRender(t *testing.T) {
	f := newFakeRouterWeb(t, fakeMap{80, "TCP", 8080, "192.168.1.2", "Web"}, fakeMap{22, "TCP", 22, "192.168.1.60", "SSH"})
	a, m := newUPnPApp(t, f, []string{f.srv.URL + "/desc.xml"})
	if err := m.RunNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, body := a.get(t, "/exposure")
	web, ssh := rowOf(body, `data-ext="tcp/80"`), rowOf(body, `data-ext="tcp/22"`)
	if web == "" || ssh == "" {
		t.Fatalf("both forwards must be listed:\n%s", body)
	}
	if !strings.Contains(web, "wahrscheinlich") || !strings.Contains(web, "erwartet") || strings.Contains(web, "unerwartet") || !strings.Contains(web, "diese Node") {
		t.Fatalf("forward to the node: %s", web)
	}
	if !strings.Contains(ssh, "unbekannt") || !strings.Contains(ssh, "unerwartet") || !strings.Contains(ssh, "192.168.1.60") {
		t.Fatalf("forward to a device without listener: %s", ssh)
	}
	if !strings.Contains(body, "203.0.113.7") {
		t.Fatal("the external address of the router must show")
	}
}

func TestExposureReachOffExplains(t *testing.T) {
	a, _ := newExposureApp(t, testSockets, true, nil, nil)
	_, body := a.get(t, "/exposure")
	if strings.Contains(body, `data-ext=`) || !strings.Contains(body, "Router per UPnP fragen") {
		t.Fatal("UPnP off: explain, no table")
	}
}

func TestExposureReachNoGateway(t *testing.T) {
	f := newFakeRouterWeb(t)
	a, m := newUPnPApp(t, f, nil)
	if err := m.RunNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, body := a.get(t, "/exposure")
	if !strings.Contains(body, "Kein Router gefunden") {
		t.Fatal("the reason must show")
	}
}

func TestExposureExpectedFlow(t *testing.T) {
	f := newFakeRouterWeb(t, fakeMap{22, "TCP", 22, "192.168.1.60", "SSH"})
	a, m := newUPnPApp(t, f, []string{f.srv.URL + "/desc.xml"})
	ctx := context.Background()
	_ = m.RunNow(ctx)
	csrf := exposureCSRF(t, a)
	resp, _ := a.post(t, "/exposure/expected", url.Values{"_csrf": {csrf}, "proto": {"tcp"}, "port": {"22"}, "note": {"Fernwartung"}})
	if resp.StatusCode != 303 {
		t.Fatalf("add: %d", resp.StatusCode)
	}
	_, body := a.get(t, "/exposure")
	if row := rowOf(body, `data-ext="tcp/22"`); strings.Contains(row, "unerwartet") || !strings.Contains(row, "erwartet") {
		t.Fatalf("an expected port must be classified as expected: %s", row)
	}
	if !strings.Contains(body, "Fernwartung") {
		t.Fatal("the note must show in the list of expected ports")
	}
	// ungueltiger Port
	a.post(t, "/exposure/expected", url.Values{"_csrf": {csrf}, "proto": {"tcp"}, "port": {"0"}})
	if _, body := a.get(t, "/exposure"); !strings.Contains(body, "Ungültiger Port") {
		t.Fatal("error flash missing")
	}
	// entfernen
	a.post(t, "/exposure/expected/delete", url.Values{"_csrf": {csrf}, "proto": {"tcp"}, "port": {"22"}})
	if list, _ := m.Expecteds(ctx); len(list) != 0 {
		t.Fatalf("not removed: %+v", list)
	}
	_, body = a.get(t, "/exposure")
	if row := rowOf(body, `data-ext="tcp/22"`); !strings.Contains(row, "unerwartet") {
		t.Fatalf("after removal it is unexpected again: %s", row)
	}
}

func TestExposureUPnPSettingsPost(t *testing.T) {
	a, m := newExposureApp(t, testSockets, true, nil, nil)
	ctx := context.Background()
	csrf := exposureCSRF(t, a)
	a.post(t, "/exposure/settings", url.Values{"_csrf": {csrf}, "interval": {"24"}, "upnp": {"on"}, "upnp_url": {"http://8.8.8.8/d.xml"}})
	if got := m.LoadSettings(ctx); got.UPnP || got.UPnPURL != "" {
		t.Fatalf("a public router address must be rejected: %+v", got)
	}
	if _, body := a.get(t, "/exposure"); !strings.Contains(body, "Ungültige Adresse des Routers") {
		t.Fatal("error flash missing")
	}
	a.post(t, "/exposure/settings", url.Values{"_csrf": {csrf}, "interval": {"24"}, "upnp": {"on"}, "upnp_url": {"http://192.168.1.1:5000/d.xml"}})
	if got := m.LoadSettings(ctx); !got.UPnP || got.UPnPURL != "http://192.168.1.1:5000/d.xml" {
		t.Fatalf("saved: %+v", got)
	}
	a.post(t, "/exposure/settings", url.Values{"_csrf": {csrf}, "interval": {"24"}})
	if got := m.LoadSettings(ctx); got.UPnP {
		t.Fatalf("an unchecked box means off: %+v", got)
	}
}

// Review Focus 4: Text des Routers ist fremder Text.
func TestExposureEscapesRouterText(t *testing.T) {
	f := newFakeRouterWeb(t, fakeMap{80, "TCP", 80, "192.168.1.60", "&lt;script&gt;x&lt;/script&gt;"})
	a, m := newUPnPApp(t, f, []string{f.srv.URL + "/desc.xml"})
	_ = m.RunNow(context.Background())
	_, body := a.get(t, "/exposure")
	if strings.Contains(body, "<script>x</script>") || !strings.Contains(body, "&lt;script&gt;x&lt;/script&gt;") {
		t.Fatal("the router's description must be escaped")
	}
}

func TestExposureGoneListed(t *testing.T) {
	f := newFakeRouterWeb(t, fakeMap{80, "TCP", 80, "192.168.1.60", "Web"})
	a, m := newUPnPApp(t, f, []string{f.srv.URL + "/desc.xml"})
	ctx := context.Background()
	_ = m.RunNow(ctx)
	f.setMaps() // der Router meldet jetzt nichts mehr
	_ = m.RunNow(ctx)
	_, body := a.get(t, "/exposure")
	if strings.Contains(body, `data-ext="tcp/80"`) || !strings.Contains(body, `data-gone="tcp/80"`) || !strings.Contains(body, "Kürzlich weggefallen") {
		t.Fatal("a forward that disappeared belongs in the list of recently gone ones")
	}
}

func TestExposureReachShowsRouterAddress(t *testing.T) {
	f := newFakeRouterWeb(t, fakeMap{80, "TCP", 8080, "192.168.1.2", "Web"})
	loc := f.srv.URL + "/desc.xml"
	var gateways atomic.Value
	gateways.Store([]string{loc})
	a, m := newExposureApp(t, testSockets, true, nil, func(m *exposure.Module) {
		m.SetGateways(func(context.Context) ([]string, error) { return gateways.Load().([]string), nil })
		m.SetLocalAddrs(func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.168.1.2")} })
	})
	if err := m.SaveSettings(context.Background(), exposure.Settings{IntervalHours: 24, UPnP: true}); err != nil {
		t.Fatal(err)
	}
	_ = m.RunNow(context.Background())
	_, body := a.get(t, "/exposure")
	if !strings.Contains(body, loc) || strings.Contains(body, "Mehrere Router") {
		t.Fatal("the asked router must show, without a multi-router hint")
	}
	gateways.Store([]string{loc, "http://127.0.0.1:1/other.xml"})
	_ = m.RunNow(context.Background())
	if _, body := a.get(t, "/exposure"); !strings.Contains(body, "Mehrere Router") {
		t.Fatal("several answering routers must be pointed out")
	}
}

// ---- E3: Verlauf ----

func TestExposureHistoryRender(t *testing.T) {
	f := newFakeRouterWeb(t, fakeMap{80, "TCP", 8080, "192.168.1.2", "Web"}, fakeMap{22, "TCP", 22, "192.168.1.60", "SSH"})
	a, m := newUPnPApp(t, f, []string{f.srv.URL + "/desc.xml"})
	ctx := context.Background()
	_ = m.RunNow(ctx)
	f.setMaps(fakeMap{80, "TCP", 8080, "192.168.1.2", "Web"})
	_ = m.RunNow(ctx)
	_, body := a.get(t, "/exposure")
	if !strings.Contains(body, `data-event="forward_new"`) || !strings.Contains(body, `data-event="forward_gone"`) || !strings.Contains(body, "192.168.1.60:22") {
		t.Fatal("the history must list the new and the gone forward")
	}
}

func TestExposureHistoryEmpty(t *testing.T) {
	a, _ := newExposureApp(t, testSockets, true, nil, nil)
	_, body := a.get(t, "/exposure")
	if strings.Contains(body, `data-event=`) || !strings.Contains(body, "Noch keine Änderungen") {
		t.Fatal("an empty history says so")
	}
}

// Dienstnamen der Node sind fremder Text (Zweck eines Moduls): im Verlauf wird escaped.
func TestExposureHistoryEscapes(t *testing.T) {
	var socks atomic.Value
	socks.Store([]netstat.Listener{{Proto: "tcp", Addr: netip.MustParseAddr("::"), Port: 8080}})
	a, m := newExposureApp(t, testSockets, true, []ports.Claim{{Owner: "web", Purpose: "<script>x</script>", Proto: ports.TCP, Port: 9000, Active: true}}, func(m *exposure.Module) {
		m.SetListeners(func() ([]netstat.Listener, bool) { return socks.Load().([]netstat.Listener), true })
	})
	socks.Store([]netstat.Listener{{Proto: "tcp", Addr: netip.MustParseAddr("::"), Port: 8080}, {Proto: "tcp", Addr: netip.MustParseAddr("::"), Port: 9000}})
	if err := m.RunNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, body := a.get(t, "/exposure")
	if !strings.Contains(body, `data-event="listen_new"`) || strings.Contains(body, "<script>x</script>") || !strings.Contains(body, "&lt;script&gt;x&lt;/script&gt;") {
		t.Fatal("a new listening port shows in the history, escaped")
	}
}

func TestExposureKeepDaysPost(t *testing.T) {
	a, m := newExposureApp(t, testSockets, true, nil, nil)
	ctx := context.Background()
	csrf := exposureCSRF(t, a)
	a.post(t, "/exposure/settings", url.Values{"_csrf": {csrf}, "interval": {"24"}, "keep_days": {"365"}})
	if got := m.LoadSettings(ctx); got.KeepDays != 365 {
		t.Fatalf("saved: %+v", got)
	}
	a.post(t, "/exposure/settings", url.Values{"_csrf": {csrf}, "interval": {"24"}, "keep_days": {"7"}})
	if got := m.LoadSettings(ctx); got.KeepDays != 365 {
		t.Fatalf("an invalid value changes nothing: %+v", got)
	}
	if _, body := a.get(t, "/exposure"); !strings.Contains(body, "Ungültige Aufbewahrung") {
		t.Fatal("error flash missing")
	}
	a.post(t, "/exposure/settings", url.Values{"_csrf": {csrf}, "interval": {"24"}}) // Feld fehlt: Wert bleibt
	if got := m.LoadSettings(ctx); got.KeepDays != 365 {
		t.Fatalf("a form without the field keeps the value: %+v", got)
	}
}

func TestExposureNotifySettingsPost(t *testing.T) {
	a, m := newExposureApp(t, testSockets, true, nil, nil)
	ctx := context.Background()
	csrf := exposureCSRF(t, a)
	if got := m.LoadSettings(ctx); !got.NotifyUnexpected || got.NotifyNew || got.NotifyListen {
		t.Fatalf("defaults: %+v", got)
	}
	a.post(t, "/exposure/settings", url.Values{"_csrf": {csrf}, "interval": {"24"}, "notify_new": {"on"}, "notify_listen": {"on"}})
	if got := m.LoadSettings(ctx); got.NotifyUnexpected || !got.NotifyNew || !got.NotifyListen {
		t.Fatalf("an unchecked box means off: %+v", got)
	}
	a.post(t, "/exposure/settings", url.Values{"_csrf": {csrf}, "interval": {"24"}, "notify_unexpected": {"on"}})
	if got := m.LoadSettings(ctx); !got.NotifyUnexpected || got.NotifyNew || got.NotifyListen {
		t.Fatalf("as in the form: %+v", got)
	}
}

// Das Formular muss jedes Feld der Einstellungen tragen, sonst setzt jedes Speichern es zurueck.
func TestExposureSettingsFormCarriesAllFields(t *testing.T) {
	a, _ := newExposureApp(t, testSockets, true, nil, nil)
	_, body := a.get(t, "/exposure")
	fields := map[string]string{"IntervalHours": "interval", "Ports": "ports", "Subnets": "subnet", "UPnP": "upnp", "UPnPURL": "upnp_url", "KeepDays": "keep_days",
		"NotifyUnexpected": "notify_unexpected", "NotifyNew": "notify_new", "NotifyListen": "notify_listen"}
	typ := reflect.TypeOf(exposure.Settings{})
	if typ.NumField() != len(fields) {
		t.Fatalf("Settings has %d fields, the test knows %d: add the new field to the form and to this list", typ.NumField(), len(fields))
	}
	for i := 0; i < typ.NumField(); i++ {
		name, ok := fields[typ.Field(i).Name]
		if !ok {
			t.Fatalf("unknown field %s", typ.Field(i).Name)
		}
		// "subnet" kommt nur mit IPAM-Subnetzen auf die Seite, die uebrigen immer
		if name != "subnet" && !strings.Contains(body, `name="`+name+`"`) {
			t.Fatalf("the form has no input %q", name)
		}
	}
	if !regexp.MustCompile(`name="notify_unexpected"[^>]*checked`).MatchString(body) {
		t.Fatal("the unexpected-forward alert is checked by default")
	}
}
