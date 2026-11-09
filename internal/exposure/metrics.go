package exposure

import (
	"context"
	"sort"
	"time"

	"github.com/ipv64net/node64/internal/metrics"
)

// Metrics: Kennzahlen fuer GET /api/metrics (Prometheus). Alles stammt aus der Datenbank, es gibt keine Netzabfrage.
func (m *Module) Metrics(ctx context.Context, w *metrics.Writer) {
	rows, err := m.Listening(ctx, "")
	if err != nil {
		m.log.Debug("exposure: metrics", "err", err)
		return
	}
	node := map[string]int{"tcp": 0, "udp": 0}
	devices := map[string]int{}
	for _, l := range rows {
		switch {
		case l.State != "open":
		case l.Address == SelfAddress:
			node[l.Proto]++
		default:
			devices[l.Address]++
		}
	}
	for _, proto := range []string{"tcp", "udp"} {
		w.Gauge("node64_exposure_node_ports", "Offene Ports der Node je Protokoll.", float64(node[proto]), "proto", proto)
	}
	addrs := make([]string, 0, len(devices))
	for a := range devices {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	for _, a := range addrs {
		w.Gauge("node64_exposure_device_ports", "Offene Ports je Geraet laut letztem Scan.", float64(devices[a]), "address", a)
	}

	open, _, _ := m.reachOverview(ctx, rows, nil)
	type lc struct {
		level Level
		class Class
	}
	forwards := map[lc]int{}
	for _, r := range open {
		forwards[lc{r.Level, r.Class}]++
	}
	for _, level := range []Level{LevelLikely, LevelUnknown} {
		for _, class := range []Class{ClassExpected, ClassUnexpected} {
			w.Gauge("node64_exposure_forwards", "Weiterleitungen des Routers je Vertrauensstufe und Einordnung.", float64(forwards[lc{level, class}]),
				"level", string(level), "class", string(class))
		}
	}

	if m.LoadSettings(ctx).UPnP {
		st := m.Status()
		w.Gauge("node64_exposure_upnp_ok", "Die letzte Abfrage des Routers war erfolgreich.", metrics.Bool(!st.UPnPAt.IsZero() && st.UPnPErr == ""))
		if !st.UPnPAt.IsZero() {
			w.Gauge("node64_exposure_upnp_last_seconds", "Letzte erfolgreiche Abfrage des Routers (Unix-Zeit).", float64(st.UPnPAt.Unix()))
		}
	}

	counts := m.eventCountsSince(ctx, time.Now().UTC().Add(-24*time.Hour))
	for _, kind := range []string{EventForwardNew, EventForwardGone, EventListenNew, EventListenGone} {
		w.Gauge("node64_exposure_events_24h", "Ereignisse des Verlaufs in den letzten 24 Stunden je Art.", float64(counts[kind]), "kind", kind)
	}
}
