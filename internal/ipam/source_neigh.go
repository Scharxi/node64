package ipam

import (
	"context"
	"net/netip"

	"github.com/ipv64net/node64/internal/dns64/groups"
)

// neighborFn liest die Nachbartabelle des Hosts (Tests ersetzen sie).
var neighborFn = groups.NeighborStates

type neighborSource struct{}

// NeighborSource liefert IP und MAC aus der Nachbartabelle (ARP/NDP, nur Linux und nur im selben Netzsegment bzw. mit
// Host-Netzwerk). Veraltete Eintraege (STALE) gelten nicht als Beweis der Anwesenheit.
func NeighborSource() Source { return neighborSource{} }

func (neighborSource) Name() string { return SourceNeighbor }

func (neighborSource) Collect(ctx context.Context) ([]Observation, error) {
	m, err := neighborFn()
	if err != nil {
		return nil, err
	}
	out := make([]Observation, 0, len(m))
	for ip, n := range m {
		if n.Stale || !ip.IsValid() {
			continue
		}
		out = append(out, Observation{IP: netip.Addr(ip), MAC: n.MAC, Source: SourceNeighbor})
	}
	return out, nil
}
