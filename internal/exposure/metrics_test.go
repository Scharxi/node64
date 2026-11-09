package exposure

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/metrics"
)

func metricsText(t *testing.T, m *Module) string {
	t.Helper()
	w := metrics.New()
	m.Metrics(context.Background(), w)
	var b bytes.Buffer
	if _, err := w.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func hasLine(out, line string) bool {
	for _, l := range strings.Split(out, "\n") {
		if l == line {
			return true
		}
	}
	return false
}

func TestMetricsValues(t *testing.T) {
	m := cardWithUPnP(t, true)
	ctx, now := context.Background(), time.Now().UTC()
	_ = m.recordSelf(ctx, now, []Listen{selfRow("tcp", 8080), selfRow("tcp", 9000), selfRow("udp", 5353)})
	_ = m.recordHost(ctx, now, netip.MustParseAddr("192.168.1.5"), []PortResult{{22, StateOpen}})
	_ = m.AddExpected(ctx, "tcp", 443, "Web")
	_ = m.recordExternal(ctx, now, EvidenceUPnP, []External{fwd(443, "192.168.1.5"), fwd(22, "192.168.1.5")})
	m.st.upnpAt = now
	out := metricsText(t, m)
	for _, line := range []string{
		`node64_exposure_node_ports{proto="tcp"} 2`,
		`node64_exposure_node_ports{proto="udp"} 1`,
		`node64_exposure_device_ports{address="192.168.1.5"} 1`,
		`node64_exposure_forwards{level="likely",class="unexpected"} 1`,
		`node64_exposure_forwards{level="unknown",class="expected"} 1`,
		`node64_exposure_forwards{level="likely",class="expected"} 0`,
		`node64_exposure_forwards{level="unknown",class="unexpected"} 0`,
		`node64_exposure_upnp_ok 1`,
		`node64_exposure_events_24h{kind="forward_new"} 2`,
		`node64_exposure_events_24h{kind="forward_gone"} 0`,
		`node64_exposure_events_24h{kind="listen_new"} 0`,
		`node64_exposure_events_24h{kind="listen_gone"} 0`,
	} {
		if !hasLine(out, line) {
			t.Fatalf("missing %q in:\n%s", line, out)
		}
	}
	if !strings.Contains(out, "node64_exposure_upnp_last_seconds ") {
		t.Fatalf("last query time missing:\n%s", out)
	}
}

func TestMetricsUPnPRowsOnlyWhenOn(t *testing.T) {
	m := cardWithUPnP(t, false)
	out := metricsText(t, m)
	if strings.Contains(out, "upnp_ok") || strings.Contains(out, "upnp_last_seconds") {
		t.Fatalf("UPnP off: no UPnP rows:\n%s", out)
	}
	on := cardWithUPnP(t, true)
	out = metricsText(t, on)
	if !hasLine(out, "node64_exposure_upnp_ok 0") || strings.Contains(out, "upnp_last_seconds") {
		t.Fatalf("UPnP on without a query: ok 0, no time:\n%s", out)
	}
}

// Review Focus 5: Sonderzeichen in einer Adresse brechen die Ausgabe nicht.
func TestMetricsSpecialCharsInAddress(t *testing.T) {
	m := cardWithUPnP(t, false)
	ts := time.Now().UTC().Format(time.RFC3339)
	if _, err := m.core.Writer().ExecContext(context.Background(), `INSERT INTO exposure_listen (address, proto, port, state, first_seen, last_seen, source) VALUES (?, 'tcp', 80, 'open', ?, ?, 'scan')`,
		"a\"b\\nc\nd", ts, ts); err != nil {
		t.Fatal(err)
	}
	out := metricsText(t, m)
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.HasPrefix(l, "#") {
			continue
		}
		if strings.Count(strings.ReplaceAll(l, `\"`, ""), `"`)%2 != 0 {
			t.Fatalf("unbalanced quotes: %q", l)
		}
		if !strings.HasPrefix(l, "node64_exposure_") {
			t.Fatalf("a raw line break split a label: %q", l)
		}
	}
	if !strings.Contains(out, `address="a\"b\\nc\nd"`) {
		t.Fatalf("address is escaped:\n%s", out)
	}
}

func TestMetricsEmpty(t *testing.T) {
	m := newTestModule(t)
	out := metricsText(t, m)
	for _, line := range []string{`node64_exposure_node_ports{proto="tcp"} 0`, `node64_exposure_forwards{level="likely",class="expected"} 0`, `node64_exposure_events_24h{kind="listen_new"} 0`} {
		if !hasLine(out, line) {
			t.Fatalf("missing %q in:\n%s", line, out)
		}
	}
}
