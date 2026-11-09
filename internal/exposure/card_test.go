package exposure

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/module"
)

func cardStat(c *module.Card, key string) (module.CardStat, bool) {
	for _, s := range c.Stats {
		if s.LabelKey == key {
			return s, true
		}
	}
	return module.CardStat{}, false
}

func cardWithUPnP(t *testing.T, on bool) *Module {
	t.Helper()
	m := newTestModule(t)
	if err := m.saveRaw(context.Background(), Settings{IntervalHours: 24, KeepDays: 90, UPnP: on, NotifyUnexpected: true}); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCardCounts(t *testing.T) {
	m := cardWithUPnP(t, true)
	ctx, now := context.Background(), time.Now().UTC()
	_ = m.recordSelf(ctx, now, []Listen{selfRow("tcp", 8080), selfRow("tcp", 9000)})
	_ = m.recordHost(ctx, now, netip.MustParseAddr("192.168.1.5"), []PortResult{{22, StateOpen}})
	_ = m.AddExpected(ctx, "tcp", 443, "Web")
	_ = m.recordExternal(ctx, now, EvidenceUPnP, []External{fwd(443, "192.168.1.5"), fwd(22, "192.168.1.5")})
	c, err := m.Card(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c.TitleKey != "nav.exposure" || c.Icon != "bi-shield-exclamation" || c.Path != "/exposure" || c.Err != "" {
		t.Fatalf("card: %+v", c)
	}
	want := map[string]int64{"exposure.card.node": 2, "exposure.card.hosts": 1, "exposure.card.forwards": 2, "exposure.card.unexpected": 1, "exposure.card.changes": 2}
	for key, v := range want {
		s, ok := cardStat(c, key)
		if !ok || s.Value != v {
			t.Fatalf("%s: %+v (want %d)", key, s, v)
		}
	}
	if s, _ := cardStat(c, "exposure.card.unexpected"); s.Class != "text-danger" {
		t.Fatalf("unexpected forwards are red: %+v", s)
	}
	if s, _ := cardStat(c, "exposure.card.node"); s.Class != "" {
		t.Fatalf("open ports of the node have no class: %+v", s)
	}
}

func TestCardHidesUPnPRowsWhenOff(t *testing.T) {
	m := cardWithUPnP(t, false)
	c, err := m.Card(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"exposure.card.forwards", "exposure.card.unexpected"} {
		if _, ok := cardStat(c, key); ok {
			t.Fatalf("%s is hidden while UPnP is off", key)
		}
	}
	for _, key := range []string{"exposure.card.node", "exposure.card.hosts", "exposure.card.changes"} {
		if _, ok := cardStat(c, key); !ok {
			t.Fatalf("%s stays", key)
		}
	}
}

func TestCardNoGatewayLeavesErrEmpty(t *testing.T) {
	m := cardWithUPnP(t, true)
	m.st.upnpErr = "no gateway found"
	c, _ := m.Card(context.Background())
	if c.Err != "" {
		t.Fatalf("err: %q", c.Err)
	}
}

func TestCardErrShowsRouterError(t *testing.T) {
	m := cardWithUPnP(t, true)
	m.st.upnpErr = "soap: 500"
	c, _ := m.Card(context.Background())
	if c.Err != "soap: 500" {
		t.Fatalf("err: %q", c.Err)
	}
	// ausgeschaltet: der alte Fehler gehoert nicht auf die Karte
	if err := m.saveRaw(context.Background(), Settings{IntervalHours: 24, KeepDays: 90}); err != nil {
		t.Fatal(err)
	}
	if c, _ := m.Card(context.Background()); c.Err != "" {
		t.Fatalf("UPnP off: %q", c.Err)
	}
}

func TestCardEmptyModule(t *testing.T) {
	m := newTestModule(t)
	c, err := m.Card(context.Background())
	if err != nil || c == nil {
		t.Fatalf("card: %v %v", c, err)
	}
	for _, s := range c.Stats {
		if s.Value != 0 || s.Class != "" {
			t.Fatalf("empty module: %+v", s)
		}
	}
	if len(c.Stats) != 3 {
		t.Fatalf("rows without UPnP: %+v", c.Stats)
	}
}

func TestCardChangesOnlyLast24Hours(t *testing.T) {
	m := cardWithUPnP(t, false)
	ctx := context.Background()
	_ = m.recordExternal(ctx, time.Now().UTC().Add(-48*time.Hour), EvidenceUPnP, []External{fwd(22, "192.168.1.5")})
	c, _ := m.Card(ctx)
	if s, _ := cardStat(c, "exposure.card.changes"); s.Value != 0 {
		t.Fatalf("a two day old event does not count: %+v", s)
	}
}
