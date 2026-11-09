package exposure

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/ipv64net/node64/internal/netstat"
	"github.com/ipv64net/node64/internal/ports"
)

func selfModule(ls []netstat.Listener, ok bool, claims []ports.Claim) *Module {
	m := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	m.SetListeners(func() ([]netstat.Listener, bool) { return ls, ok })
	m.SetClaims(func(context.Context) []ports.Claim { return claims })
	return m
}

func find(rows []Listen, proto string, port int) (Listen, bool) {
	for _, r := range rows {
		if r.Proto == proto && r.Port == port {
			return r, true
		}
	}
	return Listen{}, false
}

func TestReadSelfMapsClaims(t *testing.T) {
	m := selfModule([]netstat.Listener{
		{Proto: "tcp", Addr: netip.MustParseAddr("::"), Port: 8080},
		{Proto: "tcp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 8080}, // dasselbe als IPv4: eine Zeile
		{Proto: "tcp", Addr: netip.MustParseAddr("127.0.0.1"), Port: 5432},
		{Proto: "udp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 53},
		{Proto: "tcp", Addr: netip.MustParseAddr("192.168.1.2"), Port: 9999},
		{Proto: "tcp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 2222}, // Claim ist nicht aktiv
	}, true, []ports.Claim{
		{Owner: "web", Purpose: "HTTP", Proto: ports.TCP, Port: 8080, Active: true},
		{Owner: "dns64", Purpose: "DNS", Proto: ports.UDP, Port: 53, Active: true},
		{Owner: "honeypot", Purpose: "SSH", Proto: ports.TCP, Port: 2222, Active: false},
	})
	rows, known := m.readSelf(context.Background())
	if !known || len(rows) != 5 {
		t.Fatalf("rows: %d known=%v %+v", len(rows), known, rows)
	}
	web, _ := find(rows, "tcp", 8080)
	if web.Address != SelfAddress || web.Bind != "all" || web.Owner != "web" || web.Service != "HTTP" || web.Source != "self" || web.State != "open" {
		t.Fatalf("web: %+v", web)
	}
	pg, _ := find(rows, "tcp", 5432)
	if pg.Bind != "local" || pg.Owner != "" || pg.Service != "postgres" {
		t.Fatalf("postgres: %+v", pg)
	}
	dns, _ := find(rows, "udp", 53)
	if dns.Owner != "dns64" || dns.Service != "DNS" {
		t.Fatalf("dns: %+v", dns)
	}
	lan, _ := find(rows, "tcp", 9999)
	if lan.Bind != "192.168.1.2" || lan.Owner != "" {
		t.Fatalf("specific address: %+v", lan)
	}
	inactive, _ := find(rows, "tcp", 2222)
	if inactive.Owner != "" {
		t.Fatalf("inactive claim must not own the port: %+v", inactive)
	}
	for i := 1; i < len(rows); i++ { // stabile Reihenfolge: Protokoll, Port
		a, b := rows[i-1], rows[i]
		if a.Proto > b.Proto || (a.Proto == b.Proto && a.Port >= b.Port) {
			t.Fatalf("order: %+v then %+v", a, b)
		}
	}
}

func TestReadSelfAllBeatsLocalOnSamePort(t *testing.T) {
	m := selfModule([]netstat.Listener{
		{Proto: "tcp", Addr: netip.MustParseAddr("127.0.0.1"), Port: 53},
		{Proto: "tcp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 53},
	}, true, nil)
	rows, _ := m.readSelf(context.Background())
	if len(rows) != 1 || rows[0].Bind != "all" {
		t.Fatalf("merge: %+v", rows)
	}
}

func TestReadSelfUnknownWhenProcMissing(t *testing.T) {
	m := selfModule(nil, false, nil)
	rows, known := m.readSelf(context.Background())
	if known || len(rows) != 0 {
		t.Fatalf("unknown expected: known=%v rows=%v", known, rows)
	}
}
