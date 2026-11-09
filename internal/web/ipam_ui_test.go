package web

import (
	"context"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/ipam"
)

// newIpamApp: Web-Server mit eingeschaltetem IPAM-Modul und angemeldetem Benutzer.
func newIpamApp(t *testing.T) (*testApp, *ipam.Module) { return newIpamAppWith(t, nil) }

// newIpamAppWith: wie newIpamApp; setup richtet das Modul vor dem Start ein (z. B. Quellen).
func newIpamAppWith(t *testing.T, setup func(*ipam.Module)) (*testApp, *ipam.Module) {
	t.Helper()
	var m *ipam.Module
	a := newTestAppDeps(t, func(d *Deps) {
		m = ipam.New(d.Store, d.Log.Slog(), "test")
		if setup != nil {
			setup(m)
		}
		d.Modules.Register(m)
	})
	ctx := context.Background()
	_ = a.store.SetModuleEnabled(ctx, ipam.Name, true)
	a.registry.StartEnabled(ctx)
	t.Cleanup(a.registry.StopAll)
	loginAs(t, a, "admin", "sehr geheimes passwort")
	return a, m
}

func ipamObs(ip, name string) ipam.Observation {
	return ipam.Observation{IP: netip.MustParseAddr(ip), Name: name, Source: ipam.SourceNeighbor}
}

func ipamCSRF(t *testing.T, a *testApp) string {
	t.Helper()
	_, body := a.get(t, "/ipam")
	return csrfOf(t, body)
}

func TestIpamPageRender(t *testing.T) {
	a, m := newIpamApp(t)
	ctx := context.Background()
	s, err := m.AddSubnet(ctx, "Heim", "192.168.1.0/24", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddAddress(ctx, s.ID, "192.168.1.5", ipam.AddressEdit{Name: "<script>x</script>"}); err != nil {
		t.Fatal(err)
	}
	resp, body := a.get(t, "/ipam")
	if resp.StatusCode != 200 {
		t.Fatalf("page: %d", resp.StatusCode)
	}
	for _, want := range []string{"Heim", "192.168.1.0/24", `data-ip="192.168.1.5"`, "&lt;script&gt;x&lt;/script&gt;"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page misses %q", want)
		}
	}
	if strings.Contains(body, "<script>x</script>") {
		t.Fatal("user text must be escaped")
	}
}

func TestIpamEmptyPageHasSubnetForm(t *testing.T) {
	a, _ := newIpamApp(t)
	resp, body := a.get(t, "/ipam")
	if resp.StatusCode != 200 || !strings.Contains(body, `action="/ipam/subnets"`) {
		t.Fatalf("empty page: %d", resp.StatusCode)
	}
}

func TestIpamSubnetAddPostValidation(t *testing.T) {
	a, m := newIpamApp(t)
	ctx := context.Background()
	csrf := ipamCSRF(t, a)
	resp, _ := a.post(t, "/ipam/subnets", url.Values{"_csrf": {csrf}, "name": {"Heim"}, "cidr": {"10.0.0.0/7"}})
	if resp.StatusCode != 303 {
		t.Fatalf("invalid cidr: %d", resp.StatusCode)
	}
	if list, _ := m.Subnets(ctx); len(list) != 0 {
		t.Fatalf("invalid subnet stored: %v", list)
	}
	if _, body := a.get(t, "/ipam"); !strings.Contains(body, "Ungültiges Netz") {
		t.Fatal("error flash missing")
	}
	resp, _ = a.post(t, "/ipam/subnets", url.Values{"_csrf": {csrf}, "name": {"Heim"}, "cidr": {"192.168.1.0/24"}})
	if resp.StatusCode != 303 {
		t.Fatalf("valid cidr: %d", resp.StatusCode)
	}
	if list, _ := m.Subnets(ctx); len(list) != 1 {
		t.Fatalf("subnet not stored: %v", list)
	}
	resp, _ = a.post(t, "/ipam/subnets", url.Values{"_csrf": {csrf}, "name": {"Doppelt"}, "cidr": {"192.168.1.0/25"}})
	if list, _ := m.Subnets(ctx); resp.StatusCode != 303 || len(list) != 1 {
		t.Fatalf("overlap must be rejected: %d %v", resp.StatusCode, list)
	}
}

func TestIpamAckAllPost(t *testing.T) {
	a, m := newIpamApp(t)
	ctx := context.Background()
	s, _ := m.AddSubnet(ctx, "Heim", "192.168.1.0/24", "")
	now := time.Now().UTC()
	_, _ = m.Ingest(ctx, now, []ipam.Observation{ipamObs("192.168.1.1", "")}) // Baseline
	_, _ = m.Ingest(ctx, now, []ipam.Observation{ipamObs("192.168.1.2", ""), ipamObs("192.168.1.3", "")})
	// Baseline-Zeile .1 zaehlt als "neu" (nur ohne Meldung), dazu .2 und .3
	if st, _ := m.Stats(ctx, now); st[s.ID].New != 3 {
		t.Fatalf("new before: %+v", st[s.ID])
	}
	resp, _ := a.post(t, "/ipam/subnets/"+strconv.FormatInt(s.ID, 10)+"/ack-all", url.Values{"_csrf": {ipamCSRF(t, a)}})
	if resp.StatusCode != 303 {
		t.Fatalf("ack-all: %d", resp.StatusCode)
	}
	if st, _ := m.Stats(ctx, now); st[s.ID].New != 0 {
		t.Fatalf("new after: %+v", st[s.ID])
	}
}

func TestIpamStatusFilter(t *testing.T) {
	a, m := newIpamApp(t)
	ctx := context.Background()
	s, _ := m.AddSubnet(ctx, "Heim", "192.168.1.0/24", "")
	now := time.Now().UTC()
	_, _ = m.Ingest(ctx, now, []ipam.Observation{ipamObs("192.168.1.1", "router")}) // Baseline
	_, _ = m.Ingest(ctx, now, []ipam.Observation{ipamObs("192.168.1.22", ""), ipamObs("192.168.1.23", "tv")})
	id := strconv.FormatInt(s.ID, 10)
	_, body := a.get(t, "/ipam?subnet="+id+"&status=new")
	if !strings.Contains(body, `data-ip="192.168.1.22"`) || strings.Contains(body, `data-ip="192.168.1.23"`) {
		t.Fatal("filter status=new must list only the unknown device")
	}
	_, body = a.get(t, "/ipam?subnet="+id)
	if !strings.Contains(body, `data-ip="192.168.1.22"`) || !strings.Contains(body, `data-ip="192.168.1.23"`) {
		t.Fatal("without filter both devices are listed")
	}
}

func TestIpamAddressPosts(t *testing.T) {
	a, m := newIpamApp(t)
	ctx := context.Background()
	s, _ := m.AddSubnet(ctx, "Heim", "192.168.1.0/24", "")
	sid := strconv.FormatInt(s.ID, 10)
	csrf := ipamCSRF(t, a)
	resp, _ := a.post(t, "/ipam/addresses", url.Values{"_csrf": {csrf}, "subnet": {sid}, "ip": {"192.168.1.5"}, "name": {"NAS"}})
	if resp.StatusCode != 303 {
		t.Fatalf("add: %d", resp.StatusCode)
	}
	list, _ := m.Addresses(ctx, s.ID)
	if len(list) != 1 || list[0].Name != "NAS" {
		t.Fatalf("added: %+v", list)
	}
	id := strconv.FormatInt(list[0].ID, 10)
	a.post(t, "/ipam/addresses/"+id, url.Values{"_csrf": {csrf}, "subnet": {sid}, "name": {"Server"}, "note": {"Keller"}, "reserved": {"on"}, "reserved_mac": {"AA-BB-CC-00-00-05"}})
	list, _ = m.Addresses(ctx, s.ID)
	if list[0].Name != "Server" || list[0].Note != "Keller" || !list[0].Reserved || list[0].ReservedMAC != "aa:bb:cc:00:00:05" {
		t.Fatalf("saved: %+v", list[0])
	}
	a.post(t, "/ipam/addresses/"+id+"/ignore", url.Values{"_csrf": {csrf}, "subnet": {sid}, "on": {"1"}})
	if list, _ = m.Addresses(ctx, s.ID); !list[0].Ignored {
		t.Fatal("ignore not set")
	}
	a.post(t, "/ipam/addresses/"+id+"/delete", url.Values{"_csrf": {csrf}, "subnet": {sid}})
	if list, _ = m.Addresses(ctx, s.ID); len(list) != 0 {
		t.Fatalf("not deleted: %+v", list)
	}
	// Subnetz loeschen
	a.post(t, "/ipam/subnets/"+sid+"/delete", url.Values{"_csrf": {csrf}})
	if subs, _ := m.Subnets(ctx); len(subs) != 0 {
		t.Fatalf("subnet not deleted: %v", subs)
	}
}

func TestIpamPageIsGoneWhenDisabled(t *testing.T) {
	a, _ := newIpamApp(t)
	_ = a.registry.Disable(context.Background(), ipam.Name)
	if resp, _ := a.get(t, "/ipam"); resp.StatusCode != 404 {
		t.Fatalf("disabled module page: %d", resp.StatusCode)
	}
}

// Im Docker-Bridge-Modus enthaelt die Nachbartabelle immer das Gateway: der Hinweis, dass MACs nur im selben
// Netzsegment kommen, darf nicht verschwinden, sobald die Quelle etwas liefert.
func TestIpamNeighborHintStaysWithEntries(t *testing.T) {
	a, m := newIpamAppWith(t, func(m *ipam.Module) {
		m.AddSource(ipam.FuncSource{N: ipam.SourceNeighbor, Fn: func(context.Context) ([]ipam.Observation, error) {
			return []ipam.Observation{ipamObs("172.17.0.1", "")}, nil
		}})
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st := m.SourceStatus(); len(st) == 1 && st[0].Count == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st := m.SourceStatus(); len(st) != 1 || st[0].Count != 1 {
		t.Fatalf("source not polled: %+v", st)
	}
	_, body := a.get(t, "/ipam")
	if !strings.Contains(body, "Die Nachbartabelle liefert nur im selben Netzsegment") {
		t.Fatal("neighbour hint missing although the source returned an entry")
	}
}
