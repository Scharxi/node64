package exposure

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func extRow(proto string, port int, addr string, iport int) External {
	return External{Proto: proto, Port: port, InternalAddr: addr, InternalPort: iport, Description: "d"}
}

func extOf(t *testing.T, m *Module, proto string, port int) External {
	t.Helper()
	rows, err := m.Externals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Proto == proto && r.Port == port {
			return r
		}
	}
	t.Fatalf("external %s/%d not found in %+v", proto, port, rows)
	return External{}
}

func TestRecordExternalUpsertAndGone(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	if err := m.recordExternal(ctx, t0, EvidenceUPnP, []External{extRow("tcp", 80, "192.168.1.5", 8080), extRow("tcp", 22, "192.168.1.6", 22)}); err != nil {
		t.Fatal(err)
	}
	t1 := t0.Add(time.Hour)
	// 22 faellt weg, 80 zeigt jetzt auf ein anderes Geraet
	if err := m.recordExternal(ctx, t1, EvidenceUPnP, []External{extRow("tcp", 80, "192.168.1.9", 80)}); err != nil {
		t.Fatal(err)
	}
	web, ssh := extOf(t, m, "tcp", 80), extOf(t, m, "tcp", 22)
	if web.State != "open" || web.InternalAddr != "192.168.1.9" || web.InternalPort != 80 || !web.FirstSeen.Equal(t0) || !web.LastSeen.Equal(t1) || web.Evidence != EvidenceUPnP {
		t.Fatalf("still forwarded: %+v", web)
	}
	if ssh.State != "gone" || !ssh.LastSeen.Equal(t0) {
		t.Fatalf("gone: %+v", ssh)
	}
	t2 := t1.Add(time.Hour)
	if err := m.recordExternal(ctx, t2, EvidenceUPnP, []External{extRow("tcp", 22, "192.168.1.6", 22)}); err != nil {
		t.Fatal(err)
	}
	if ssh = extOf(t, m, "tcp", 22); ssh.State != "open" || !ssh.FirstSeen.Equal(t0) || !ssh.LastSeen.Equal(t2) {
		t.Fatalf("reopened: %+v", ssh)
	}
}

// Review Focus 5: ein erfolgreicher Lauf ohne Weiterleitungen setzt die bekannten auf "gone".
func TestRecordExternalEmptyListMarksGone(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	_ = m.recordExternal(ctx, t0, EvidenceUPnP, []External{extRow("tcp", 80, "192.168.1.5", 80), extRow("udp", 51820, "192.168.1.5", 51820)})
	if err := m.recordExternal(ctx, t0.Add(time.Hour), EvidenceUPnP, nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		proto string
		port  int
	}{{"tcp", 80}, {"udp", 51820}} {
		if r := extOf(t, m, c.proto, c.port); r.State != "gone" {
			t.Fatalf("%s/%d must be gone: %+v", c.proto, c.port, r)
		}
	}
}

func TestRecordExternalOnlyTouchesItsEvidence(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	_ = m.recordExternal(ctx, t0, "probe", []External{extRow("tcp", 443, "", 0)})
	_ = m.recordExternal(ctx, t0, EvidenceUPnP, []External{extRow("tcp", 80, "192.168.1.5", 80)})
	if err := m.recordExternal(ctx, t0.Add(time.Hour), EvidenceUPnP, nil); err != nil {
		t.Fatal(err)
	}
	if r := extOf(t, m, "tcp", 443); r.State != "open" || r.Evidence != "probe" {
		t.Fatalf("another evidence must stay as it was: %+v", r)
	}
}

func TestExternalsOrder(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	_ = m.recordExternal(ctx, t0, EvidenceUPnP, []External{extRow("udp", 53, "192.168.1.5", 53), extRow("tcp", 443, "192.168.1.5", 443), extRow("tcp", 22, "192.168.1.5", 22)})
	rows, err := m.Externals(ctx)
	if err != nil || len(rows) != 3 {
		t.Fatalf("list: %v %v", rows, err)
	}
	if rows[0].Port != 22 || rows[1].Port != 443 || rows[2].Proto != "udp" {
		t.Fatalf("order: %+v", rows)
	}
}

func TestExpectedCRUD(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	if err := m.AddExpected(ctx, "tcp", 443, "Webserver"); err != nil {
		t.Fatal(err)
	}
	if err := m.AddExpected(ctx, "tcp", 443, "Neue Notiz"); err != nil { // aktualisiert
		t.Fatal(err)
	}
	if err := m.AddExpected(ctx, "udp", 51820, ""); err != nil {
		t.Fatal(err)
	}
	list, err := m.Expecteds(ctx)
	if err != nil || len(list) != 2 || list[0].Port != 443 || list[0].Note != "Neue Notiz" || list[1].Proto != "udp" {
		t.Fatalf("list: %+v %v", list, err)
	}
	if err := m.RemoveExpected(ctx, "tcp", 443); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveExpected(ctx, "tcp", 443); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second remove: %v", err)
	}
	if list, _ := m.Expecteds(ctx); len(list) != 1 {
		t.Fatalf("after remove: %+v", list)
	}
}

func TestAddExpectedValidation(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	for name, c := range map[string]struct {
		proto string
		port  int
		note  string
	}{
		"icmp": {"icmp", 80, ""}, "empty proto": {"", 80, ""}, "port 0": {"tcp", 0, ""}, "port 65536": {"tcp", 65536, ""},
		"long note": {"tcp", 80, strings.Repeat("a", 254)}, "newline": {"tcp", 80, "a\nb"},
	} {
		if err := m.AddExpected(ctx, c.proto, c.port, c.note); !errors.Is(err, ErrInvalidExpected) {
			t.Errorf("%s: %v, want ErrInvalidExpected", name, err)
		}
	}
	if list, _ := m.Expecteds(ctx); len(list) != 0 {
		t.Fatalf("invalid input must not be stored: %+v", list)
	}
	if err := m.AddExpected(ctx, "TCP", 8080, strings.Repeat("ä", 253)); err != nil { // Gross-/Kleinschreibung egal, 253 Zeichen ok
		t.Fatalf("valid: %v", err)
	}
	if list, _ := m.Expecteds(ctx); len(list) != 1 || list[0].Proto != "tcp" {
		t.Fatalf("proto must be stored in lower case: %+v", list)
	}
}
