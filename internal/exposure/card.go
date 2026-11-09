package exposure

import (
	"context"
	"time"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/store"
)

// errNoGateway ist der Text der Abfrage, wenn kein Router antwortet; die Karte zeigt ihn nicht (die Seite erklaert es).
const errNoGateway = "no gateway found"

// Card liefert die Karte fuers Dashboard (module.CardProvider).
func (m *Module) Card(ctx context.Context) (*module.Card, error) {
	rows, err := m.Listening(ctx, "")
	if err != nil {
		return nil, err
	}
	node, hosts := 0, map[string]bool{}
	for _, l := range rows {
		if l.State != "open" {
			continue
		}
		if l.Address == SelfAddress {
			node++
		} else {
			hosts[l.Address] = true
		}
	}
	changes, err := m.countEventsSince(ctx, time.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	c := &module.Card{TitleKey: "nav.exposure", Icon: "bi-shield-exclamation", Path: "/exposure"}
	c.Stats = []module.CardStat{
		{LabelKey: "exposure.card.node", Value: int64(node)},
		{LabelKey: "exposure.card.hosts", Value: int64(len(hosts))},
	}
	if m.LoadSettings(ctx).UPnP {
		open, _, _ := m.reachOverview(ctx, rows, nil)
		unexpected := 0
		for _, r := range open {
			if r.Class == ClassUnexpected {
				unexpected++
			}
		}
		un := module.CardStat{LabelKey: "exposure.card.unexpected", Value: int64(unexpected)}
		if unexpected > 0 {
			un.Class = "text-danger"
		}
		c.Stats = append(c.Stats, module.CardStat{LabelKey: "exposure.card.forwards", Value: int64(len(open))}, un)
		if e := m.Status().UPnPErr; e != "" && e != errNoGateway {
			c.Err = e
		}
	}
	c.Stats = append(c.Stats, module.CardStat{LabelKey: "exposure.card.changes", Value: int64(changes)})
	return c, nil
}

// countEventsSince zaehlt die Ereignisse des Verlaufs ab since (die Baseline erzeugt keine).
func (m *Module) countEventsSince(ctx context.Context, since time.Time) (int, error) {
	var n int
	err := m.core.Reader().QueryRowContext(ctx, `SELECT count(*) FROM exposure_events WHERE at >= ?`, store.FormatTime(since)).Scan(&n)
	return n, err
}

// eventCountsSince zaehlt die Ereignisse ab since je Art (bei einem Fehler leer).
func (m *Module) eventCountsSince(ctx context.Context, since time.Time) map[string]int {
	out := map[string]int{}
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT kind, count(*) FROM exposure_events WHERE at >= ? GROUP BY kind`, store.FormatTime(since))
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var n int
		if rows.Scan(&kind, &n) == nil {
			out[kind] = n
		}
	}
	return out
}
