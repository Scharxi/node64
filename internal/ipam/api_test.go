package ipam

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/module"
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

func TestAPISubnets(t *testing.T) {
	m := newTestModule(t)
	srv := apiServer(t, m)
	code, body := call(t, "POST", srv.URL+"/api/ipam/subnets", map[string]any{"name": "Heim", "cidr": "192.168.1.5/24", "note": "n"})
	if code != 201 || !strings.Contains(body, `"cidr":"192.168.1.0/24"`) || !strings.Contains(body, `"id":1`) {
		t.Fatalf("create: %d %s", code, body)
	}
	if code, _ := call(t, "POST", srv.URL+"/api/ipam/subnets", map[string]any{"name": "x", "cidr": "192.168.1.0/25"}); code != 409 {
		t.Fatalf("overlap: %d", code)
	}
	if code, body := call(t, "POST", srv.URL+"/api/ipam/subnets", map[string]any{"name": "x", "cidr": "10.0.0.0/7"}); code != 422 || !strings.Contains(body, `"error"`) {
		t.Fatalf("invalid: %d %s", code, body)
	}
	if code, _ := call(t, "POST", srv.URL+"/api/ipam/subnets", "{not json"); code != 400 {
		t.Fatalf("bad json: %d", code)
	}
	if code, body := call(t, "GET", srv.URL+"/api/ipam/subnets", nil); code != 200 || !strings.Contains(body, `"size":254`) || !strings.Contains(body, `"name":"Heim"`) {
		t.Fatalf("list: %d %s", code, body)
	}
	if code, _ := call(t, "DELETE", srv.URL+"/api/ipam/subnets/1", nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := call(t, "DELETE", srv.URL+"/api/ipam/subnets/1", nil); code != 404 {
		t.Fatalf("second delete: %d", code)
	}
	if code, _ := call(t, "GET", srv.URL+"/api/ipam/subnets/1/addresses", nil); code != 404 {
		t.Fatalf("addresses of missing subnet: %d", code)
	}
}

func TestAPIAddresses(t *testing.T) {
	m, v4, _ := ingestEnv(t)
	ctx := context.Background()
	srv := apiServer(t, m)
	base := srv.URL + "/api/ipam/subnets/" + strconv.FormatInt(v4.ID, 10) + "/addresses"

	code, body := call(t, "POST", base, map[string]any{"ip": "192.168.1.5", "name": "NAS", "reserved": true, "reserved_mac": "AA-BB-CC-00-00-05"})
	if code != 201 || !strings.Contains(body, `"name":"NAS"`) || !strings.Contains(body, `"reserved_mac":"aa:bb:cc:00:00:05"`) || !strings.Contains(body, `"status":"reserved"`) {
		t.Fatalf("create: %d %s", code, body)
	}
	if code, _ := call(t, "POST", base, map[string]any{"ip": "192.168.1.5"}); code != 409 {
		t.Fatalf("duplicate: %d", code)
	}
	if code, _ := call(t, "POST", base, map[string]any{"ip": "10.1.1.1"}); code != 422 {
		t.Fatalf("outside: %d", code)
	}
	if code, _ := call(t, "POST", base, map[string]any{"ip": "192.168.1.6", "reserved_mac": "zz"}); code != 422 {
		t.Fatalf("bad mac: %d", code)
	}

	now := time.Now().UTC()
	_, _ = m.Ingest(ctx, now, []Observation{obs("192.168.1.1", "", "router", SourceDNS64)}) // Baseline
	_, _ = m.Ingest(ctx, now, []Observation{obs("192.168.1.9", "aa:bb:cc:00:00:09", "", SourceNeighbor), obs("192.168.1.10", "", "", SourceNeighbor)})
	code, body = call(t, "GET", base+"?status=new", nil)
	if code != 200 || !strings.Contains(body, `"ip":"192.168.1.9"`) || strings.Contains(body, `"ip":"192.168.1.5"`) || !strings.Contains(body, `"mac":"aa:bb:cc:00:00:09"`) {
		t.Fatalf("filter new: %d %s", code, body)
	}
	if code, _ := call(t, "GET", base+"?status=bogus", nil); code != 422 {
		t.Fatalf("bad status: %d", code)
	}

	nine := addrOf(t, m, v4, "192.168.1.9")
	url := srv.URL + "/api/ipam/addresses/" + strconv.FormatInt(nine.ID, 10)
	if code, body := call(t, "PUT", url, map[string]any{"name": "Drucker", "note": "Flur"}); code != 200 || !strings.Contains(body, `"name":"Drucker"`) {
		t.Fatalf("update: %d %s", code, body)
	}
	if code, _ := call(t, "PUT", srv.URL+"/api/ipam/addresses/999", map[string]any{"name": "x"}); code != 404 {
		t.Fatalf("update missing: %d", code)
	}
	if code, _ := call(t, "POST", url+"/ack", nil); code != 204 {
		t.Fatalf("ack: %d", code)
	}
	code, body = call(t, "POST", srv.URL+"/api/ipam/subnets/"+strconv.FormatInt(v4.ID, 10)+"/ack-all", nil)
	if code != 200 || !strings.Contains(body, `"acknowledged":`) {
		t.Fatalf("ack-all: %d %s", code, body)
	}
	if code, _ := call(t, "DELETE", url, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := call(t, "DELETE", url, nil); code != 404 {
		t.Fatalf("second delete: %d", code)
	}
}

func TestAPIStatus(t *testing.T) {
	m, _, _ := ingestEnv(t)
	m.AddSource(FuncSource{N: "x", Fn: func(context.Context) ([]Observation, error) { return nil, nil }})
	srv := apiServer(t, m)
	code, body := call(t, "GET", srv.URL+"/api/ipam/status", nil)
	if code != 200 || !strings.Contains(body, `"subnets":2`) || !strings.Contains(body, `"sources":[{"name":"x"`) || !strings.Contains(body, `"outside":0`) {
		t.Fatalf("status: %d %s", code, body)
	}
}
