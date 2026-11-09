package exposure

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/netstat"
)

func apiServer(t *testing.T, m *Module) *httptest.Server {
	t.Helper()
	pass := func(h http.Handler) http.Handler { return h }
	mux := http.NewServeMux()
	m.Routes(mux, module.Guards{Enabled: pass, Auth: pass, Actor: func(*http.Request) string { return "test" }})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func call(t *testing.T, method, url string, body any) (int, string) {
	t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, url, rd)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func apiModule(t *testing.T) *Module {
	t.Helper()
	m := newTestModule(t)
	fakeIPAM(m, []SubnetRef{{ID: 1, Name: "Heim", CIDR: netip.MustParsePrefix("192.168.1.0/24")}}, nil)
	m.SetListeners(func() ([]netstat.Listener, bool) {
		return []netstat.Listener{{Proto: "tcp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 8080}}, true
	})
	return m
}

func TestAPIStatus(t *testing.T) {
	m := apiModule(t)
	srv := apiServer(t, m)
	_ = m.snapshotSelf(context.Background(), t0)
	code, body := call(t, "GET", srv.URL+"/api/exposure/status", nil)
	if code != 200 || !strings.Contains(body, `"self_known":true`) || !strings.Contains(body, `"running":false`) || !strings.Contains(body, `"last_self_at":"2026-11-09T12:00:00Z"`) {
		t.Fatalf("status: %d %s", code, body)
	}
}

func TestAPIListenFilter(t *testing.T) {
	m := apiModule(t)
	ctx := context.Background()
	srv := apiServer(t, m)
	_ = m.snapshotSelf(ctx, t0)
	_ = m.recordHost(ctx, t0, netip.MustParseAddr("192.168.1.20"), []PortResult{{22, StateOpen}})
	code, body := call(t, "GET", srv.URL+"/api/exposure/listen?address=self", nil)
	if code != 200 || !strings.Contains(body, `"port":8080`) || strings.Contains(body, `"port":22`) || !strings.Contains(body, `"bind":"all"`) {
		t.Fatalf("self: %d %s", code, body)
	}
	code, body = call(t, "GET", srv.URL+"/api/exposure/listen?address=192.168.1.20", nil)
	if code != 200 || !strings.Contains(body, `"port":22`) || !strings.Contains(body, `"service":"ssh"`) || !strings.Contains(body, `"source":"scan"`) {
		t.Fatalf("host: %d %s", code, body)
	}
	if code, body := call(t, "GET", srv.URL+"/api/exposure/listen", nil); code != 200 || !strings.Contains(body, `"port":8080`) || !strings.Contains(body, `"port":22`) {
		t.Fatalf("all: %d %s", code, body)
	}
	if code, _ := call(t, "GET", srv.URL+"/api/exposure/listen?address=not-an-ip", nil); code != 422 {
		t.Fatalf("invalid address: %d", code)
	}
}

func TestAPISettings(t *testing.T) {
	m := apiModule(t)
	srv := apiServer(t, m)
	code, body := call(t, "GET", srv.URL+"/api/exposure/settings", nil)
	if code != 200 || !strings.Contains(body, `"interval_hours":24`) || !strings.Contains(body, `"ports":[]`) || !strings.Contains(body, `"subnets":[]`) {
		t.Fatalf("defaults: %d %s", code, body)
	}
	code, body = call(t, "PUT", srv.URL+"/api/exposure/settings", map[string]any{"interval_hours": 6, "ports": []int{40001}, "subnets": []int{1}})
	if code != 200 || !strings.Contains(body, `"interval_hours":6`) || !strings.Contains(body, `"ports":[40001]`) || !strings.Contains(body, `"subnets":[1]`) {
		t.Fatalf("put: %d %s", code, body)
	}
	many := make([]int, 100)
	for i := range many {
		many[i] = 40000 + i
	}
	for name, in := range map[string]map[string]any{
		"interval": {"interval_hours": 7, "ports": []int{}, "subnets": []int{}},
		"too many": {"interval_hours": 24, "ports": many, "subnets": []int{}},
		"port 0":   {"interval_hours": 24, "ports": []int{0}, "subnets": []int{}},
		"subnet":   {"interval_hours": 24, "ports": []int{}, "subnets": []int{99}},
	} {
		if code, body := call(t, "PUT", srv.URL+"/api/exposure/settings", in); code != 422 || !strings.Contains(body, `"error"`) {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	if code, _ := call(t, "PUT", srv.URL+"/api/exposure/settings", "{not json"); code != 400 {
		t.Fatalf("bad json: %d", code)
	}
	if code, body := call(t, "GET", srv.URL+"/api/exposure/settings", nil); code != 200 || !strings.Contains(body, `"interval_hours":6`) {
		t.Fatalf("invalid input must not change anything: %d %s", code, body)
	}
}

func TestAPIScan(t *testing.T) {
	fastScan(t)
	m := apiModule(t)
	srv := apiServer(t, m)
	code, body := call(t, "POST", srv.URL+"/api/exposure/scan", nil)
	if code != 202 || !strings.Contains(body, `"started":true`) {
		t.Fatalf("scan: %d %s", code, body)
	}
	deadline := time.Now().Add(3 * time.Second) // der Lauf haengt am Store: abwarten, bevor der Test ihn schliesst
	for time.Now().Before(deadline) {
		if st := m.Status(); !st.Running && !st.LastSelfAt.IsZero() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("run did not finish")
}

func TestAPIScanBusy(t *testing.T) {
	fastScan(t)
	m := apiModule(t)
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	var first atomic.Bool
	m.SetHosts(func(context.Context, int64) ([]HostRef, error) {
		if first.CompareAndSwap(false, true) {
			entered <- struct{}{}
			<-release
		}
		return nil, nil
	})
	if err := m.SaveSettings(context.Background(), Settings{IntervalHours: 24, Subnets: []int64{1}}); err != nil {
		t.Fatal(err)
	}
	srv := apiServer(t, m)
	done := make(chan error, 1)
	go func() { done <- m.RunNow(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first run did not start")
	}
	if code, body := call(t, "POST", srv.URL+"/api/exposure/scan", nil); code != 409 || !strings.Contains(body, `"error"`) {
		t.Fatalf("busy: %d %s", code, body)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// ---- Spur 2 ----

// upnpAPI: API-Modul mit Fake-Router; die Node hat die Adresse 192.168.1.5 und lauscht auf 8080 (ohne Besitzer).
func upnpAPI(t *testing.T, entries ...fakeEntry) (*Module, *fakeIGD, *httptest.Server) {
	t.Helper()
	f := newFakeIGD(t, entries...)
	m := apiModule(t)
	m.SetGateways(func(context.Context) ([]string, error) { return []string{f.url("/desc.xml")}, nil })
	o, _ := testUPnPOptions()
	m.SetUPnPOptions(o)
	m.SetLocalAddrs(func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.168.1.5")} })
	if err := m.SaveSettings(context.Background(), Settings{IntervalHours: 24, UPnP: true}); err != nil {
		t.Fatal(err)
	}
	return m, f, apiServer(t, m)
}

func TestAPIOverview(t *testing.T) {
	fastScan(t)
	m, f, srv := upnpAPI(t, fakeEntry{80, "TCP", 8080, "192.168.1.5", "1", "Web"}, fakeEntry{22, "TCP", 22, "192.168.1.60", "1", "SSH"})
	if err := m.RunNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	code, body := call(t, "GET", srv.URL+"/api/exposure/overview", nil)
	if code != 200 || !strings.Contains(body, `"enabled":true`) || !strings.Contains(body, `"external_ip":"203.0.113.7"`) || !strings.Contains(body, `"mappings":2`) {
		t.Fatalf("upnp part: %d %s", code, body)
	}
	if !strings.Contains(body, `"port":80`) || !strings.Contains(body, `"level":"likely"`) || !strings.Contains(body, `"device":"self"`) || !strings.Contains(body, `"class":"unexpected"`) {
		t.Fatalf("rows: %s", body)
	}
	// erwartet eintragen: die Zeile wird "expected"
	if code, _ := call(t, "POST", srv.URL+"/api/exposure/expected", map[string]any{"proto": "tcp", "port": 80, "note": "Web"}); code != 201 {
		t.Fatalf("add expected: %d", code)
	}
	if _, body := call(t, "GET", srv.URL+"/api/exposure/overview", nil); !strings.Contains(body, `"class":"expected"`) {
		t.Fatalf("expected class: %s", body)
	}
	// Weiterleitungen weg: erscheinen unter "gone"
	f.entries = nil
	_ = m.RunNow(context.Background())
	_, body = call(t, "GET", srv.URL+"/api/exposure/overview", nil)
	if !strings.Contains(body, `"open":[]`) || !strings.Contains(body, `"gone":[{"proto":"tcp","port":22`) {
		t.Fatalf("gone: %s", body)
	}
}

func TestAPIExpectedCRUD(t *testing.T) {
	_, _, srv := upnpAPI(t)
	base := srv.URL + "/api/exposure/expected"
	if code, body := call(t, "POST", base, map[string]any{"proto": "tcp", "port": 443, "note": "Web"}); code != 201 || !strings.Contains(body, `"port":443`) {
		t.Fatalf("create: %d %s", code, body)
	}
	if code, _ := call(t, "POST", base, map[string]any{"proto": "tcp", "port": 443, "note": "Neu"}); code != 201 {
		t.Fatalf("update by create: %d", code)
	}
	if code, body := call(t, "GET", base, nil); code != 200 || !strings.Contains(body, `"note":"Neu"`) || strings.Count(body, `"port":443`) != 1 {
		t.Fatalf("list: %d %s", code, body)
	}
	for name, in := range map[string]map[string]any{"icmp": {"proto": "icmp", "port": 1}, "port 0": {"proto": "tcp", "port": 0}, "port 65536": {"proto": "tcp", "port": 65536}} {
		if code, body := call(t, "POST", base, in); code != 422 || !strings.Contains(body, `"error"`) {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	if code, _ := call(t, "POST", base, "{not json"); code != 400 {
		t.Fatalf("bad json: %d", code)
	}
	if code, _ := call(t, "DELETE", base+"/tcp/443", nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := call(t, "DELETE", base+"/tcp/443", nil); code != 404 {
		t.Fatalf("second delete: %d", code)
	}
	if code, _ := call(t, "DELETE", base+"/tcp/abc", nil); code != 422 {
		t.Fatalf("port abc: %d", code)
	}
}

func TestAPISettingsUPnP(t *testing.T) {
	m := apiModule(t)
	srv := apiServer(t, m)
	code, body := call(t, "PUT", srv.URL+"/api/exposure/settings", map[string]any{"interval_hours": 24, "ports": []int{}, "subnets": []int{}, "upnp": true, "upnp_url": "http://127.0.0.1:5000/d.xml"})
	if code != 200 || !strings.Contains(body, `"upnp":true`) || !strings.Contains(body, `"upnp_url":"http://127.0.0.1:5000/d.xml"`) {
		t.Fatalf("put: %d %s", code, body)
	}
	if code, body := call(t, "GET", srv.URL+"/api/exposure/settings", nil); code != 200 || !strings.Contains(body, `"upnp":true`) {
		t.Fatalf("get: %d %s", code, body)
	}
	if code, body := call(t, "PUT", srv.URL+"/api/exposure/settings", map[string]any{"interval_hours": 24, "upnp": true, "upnp_url": "http://8.8.8.8/d.xml"}); code != 422 || !strings.Contains(body, `"error"`) {
		t.Fatalf("public url: %d %s", code, body)
	}
	if code, body := call(t, "GET", srv.URL+"/api/exposure/settings", nil); !strings.Contains(body, `"upnp_url":"http://127.0.0.1:5000/d.xml"`) || code != 200 {
		t.Fatalf("a rejected put changes nothing: %s", body)
	}
}

func TestAPIStatusUPnP(t *testing.T) {
	fastScan(t)
	m, _, srv := upnpAPI(t, fakeEntry{80, "TCP", 8080, "192.168.1.5", "1", "Web"})
	_ = m.RunNow(context.Background())
	code, body := call(t, "GET", srv.URL+"/api/exposure/status", nil)
	if code != 200 || !strings.Contains(body, `"upnp_at":"`) || !strings.Contains(body, `"external_ip":"203.0.113.7"`) || !strings.Contains(body, `"mappings":1`) || !strings.Contains(body, `"upnp_error":""`) {
		t.Fatalf("status: %d %s", code, body)
	}
}
