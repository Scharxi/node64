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
