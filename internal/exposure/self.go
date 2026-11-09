package exposure

import (
	"context"
	"net/netip"
	"sort"
	"time"

	"github.com/ipv64net/node64/internal/netstat"
	"github.com/ipv64net/node64/internal/ports"
)

// SelfAddress ist die Adresse der Zeilen, die die Node selbst betreffen (lauschende Sockets im eigenen Namensraum).
const SelfAddress = "self"

// Listen ist ein gesehener offener Port auf einer Adresse.
type Listen struct {
	Address   string // SelfAddress oder die IP eines Geraets
	Proto     string // tcp oder udp
	Port      int
	State     string // open | gone
	Service   string // Dienst bzw. Zweck (bei der Node: Zweck des besitzenden Moduls)
	Bind      string // nur Node: all | local | <Adresse>
	Owner     string // nur Node: besitzendes Modul, leer = fremdes Programm
	FirstSeen time.Time
	LastSeen  time.Time
	Source    string // self | scan
}

// SetListeners ersetzt die Quelle der lauschenden Sockets (Standard netstat.Listeners; Tests setzen eine feste Liste).
func (m *Module) SetListeners(f func() ([]netstat.Listener, bool)) { m.listeners = f }

// SetClaims setzt die Port-Verwaltung: wem gehoert welcher Port.
func (m *Module) SetClaims(f func(ctx context.Context) []ports.Claim) { m.claims = f }

// bindRank ordnet die Bindungen: all vor einer bestimmten Adresse vor local.
func bindRank(b string) int {
	switch b {
	case "all":
		return 0
	case "local":
		return 2
	}
	return 1
}

func bindOf(a netip.Addr) string {
	switch {
	case a.IsUnspecified():
		return "all"
	case a.IsLoopback():
		return "local"
	}
	return a.Unmap().String()
}

// readSelf liest die lauschenden Sockets der Node (kein Netzverkehr). known = false, wenn /proc nicht lesbar war: dann
// ist unbekannt, was offen ist, und es duerfen keine Zeilen als "weg" gelten. Je Protokoll und Port eine Zeile
// (IPv4- und IPv6-Socket werden zusammengefasst, die weiteste Bindung gewinnt).
func (m *Module) readSelf(ctx context.Context) (rows []Listen, known bool) {
	if m.listeners == nil {
		return nil, false
	}
	ls, ok := m.listeners()
	if !ok {
		return nil, false
	}
	var claims []ports.Claim
	if m.claims != nil {
		for _, c := range m.claims(ctx) {
			if c.Active {
				claims = append(claims, c)
			}
		}
	}
	type key struct {
		proto string
		port  int
	}
	merged := map[key]Listen{}
	for _, l := range ls {
		k := key{l.Proto, l.Port}
		row := Listen{Address: SelfAddress, Proto: l.Proto, Port: l.Port, State: "open", Bind: bindOf(l.Addr), Source: "self"}
		if old, ok := merged[k]; ok && bindRank(old.Bind) <= bindRank(row.Bind) {
			continue
		}
		merged[k] = row
	}
	for k, row := range merged {
		row.Service = ServiceName(row.Proto, row.Port)
		for _, c := range claims {
			if string(c.Proto) == row.Proto && c.Port == row.Port && listenerFor(ls, row.Proto, row.Port).Covers(string(c.Proto), c.Bind, c.Port) {
				row.Owner, row.Service = c.Owner, c.Purpose
				break
			}
		}
		merged[k] = row
	}
	rows = make([]Listen, 0, len(merged))
	for _, r := range merged {
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Proto != rows[j].Proto {
			return rows[i].Proto < rows[j].Proto
		}
		return rows[i].Port < rows[j].Port
	})
	return rows, true
}

// listenerFor liefert einen Socket fuer Protokoll und Port (fuer Covers).
func listenerFor(ls []netstat.Listener, proto string, port int) netstat.Listener {
	for _, l := range ls {
		if l.Proto == proto && l.Port == port {
			return l
		}
	}
	return netstat.Listener{}
}
