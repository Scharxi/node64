package exposure

import (
	"net/netip"
	"sort"
	"time"
)

// Level ist die Vertrauensstufe einer Aussage "aus dem Internet erreichbar". E2 kennt nur "wahrscheinlich" und
// "unbekannt"; "bestaetigt" kommt erst mit einem Aussen-Messpunkt.
type Level string

const (
	LevelLikely  Level = "likely"  // der Router leitet weiter und das Ziel lauscht dort
	LevelUnknown Level = "unknown" // der Router leitet weiter, ob das Ziel dort lauscht, ist nicht bekannt
)

// Class ist die Einordnung einer Weiterleitung.
type Class string

const (
	ClassExpected   Class = "expected"
	ClassUnexpected Class = "unexpected"
)

const (
	newWindow  = 24 * time.Hour
	goneWindow = 7 * 24 * time.Hour
)

// OverviewRow ist eine Zeile der Gesamtsicht: eine Weiterleitung des Routers, zusammengefuehrt mit dem, was lauscht.
type OverviewRow struct {
	Proto        string
	Port         int // externer Port
	Level        Level
	Class        Class
	Device       string // SelfAddress, sonst Name aus IPAM, sonst die Adresse
	InternalAddr string
	InternalPort int
	Service      string
	Description  string
	Listening    bool // das Ziel lauscht laut Innen-Sicht auf dem internen Port
	New          bool // erste Sichtung vor weniger als 24 Stunden
	FirstSeen    time.Time
	LastSeen     time.Time
}

// OverviewInput sind die Daten der Gesamtsicht. Local sind die eigenen Adressen der Node (Ziel einer Weiterleitung auf
// die Node), Names die Namen aus IPAM je Adresse.
type OverviewInput struct {
	External []External
	Listen   []Listen
	Expected []Expected
	Local    []netip.Addr
	Names    map[string]string
	Now      time.Time
}

type listenKey struct {
	address, proto string
	port           int
}

// Classify fuehrt die Weiterleitungen des Routers mit der Innen-Sicht und den Erwartungen zusammen. open sind die
// aktuellen Weiterleitungen nach Port, gone die in den letzten 7 Tagen weggefallenen (neueste zuerst).
func Classify(in OverviewInput) (open []OverviewRow, gone []External) {
	local := map[netip.Addr]bool{}
	for _, a := range in.Local {
		local[a.Unmap()] = true
	}
	listening := map[listenKey]Listen{}
	for _, l := range in.Listen {
		if l.State == "open" {
			listening[listenKey{l.Address, l.Proto, l.Port}] = l
		}
	}
	expected := map[listenKey]bool{}
	for _, e := range in.Expected {
		expected[listenKey{"", e.Proto, e.Port}] = true
	}
	for _, e := range in.External {
		if e.State != "open" {
			if in.Now.Sub(e.LastSeen) <= goneWindow {
				gone = append(gone, e)
			}
			continue
		}
		row := OverviewRow{Proto: e.Proto, Port: e.Port, Level: LevelUnknown, Class: ClassUnexpected, Device: e.InternalAddr,
			InternalAddr: e.InternalAddr, InternalPort: e.InternalPort, Description: e.Description,
			New: in.Now.Sub(e.FirstSeen) < newWindow, FirstSeen: e.FirstSeen, LastSeen: e.LastSeen}
		row.Service = ServiceName(e.Proto, e.InternalPort)
		target, isSelf := "", false
		if a, err := netip.ParseAddr(e.InternalAddr); err == nil {
			a = a.Unmap()
			target = a.String()
			if local[a] {
				target, isSelf = SelfAddress, true
				row.Device = SelfAddress
			} else if name := in.Names[a.String()]; name != "" {
				row.Device = name
			}
		}
		l, ok := Listen{}, false
		if target != "" {
			l, ok = listening[listenKey{target, e.Proto, e.InternalPort}]
		}
		if ok {
			row.Listening, row.Level = true, LevelLikely
			if l.Service != "" {
				row.Service = l.Service
			}
		}
		if expected[listenKey{"", e.Proto, e.Port}] || (isSelf && ok && l.Owner != "") {
			row.Class = ClassExpected
		}
		open = append(open, row)
	}
	sort.Slice(open, func(i, j int) bool {
		if open[i].Port != open[j].Port {
			return open[i].Port < open[j].Port
		}
		return open[i].Proto < open[j].Proto
	})
	sort.Slice(gone, func(i, j int) bool { return gone[i].LastSeen.After(gone[j].LastSeen) })
	return open, gone
}
