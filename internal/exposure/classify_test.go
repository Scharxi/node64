package exposure

import (
	"net/netip"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func ext(proto string, port int, addr string, iport int, first, last time.Time, state string) External {
	return External{Proto: proto, Port: port, Evidence: EvidenceUPnP, InternalAddr: addr, InternalPort: iport, State: state, FirstSeen: first, LastSeen: last}
}

func selfListen(proto string, port int, owner, service string) Listen {
	return Listen{Address: SelfAddress, Proto: proto, Port: port, State: "open", Owner: owner, Service: service, Source: "self"}
}

func hostListen(addr string, port int, service string) Listen {
	return Listen{Address: addr, Proto: "tcp", Port: port, State: "open", Service: service, Source: "scan"}
}

func local(addrs ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

func oneRow(t *testing.T, in OverviewInput) OverviewRow {
	t.Helper()
	in.Now = now
	open, _ := Classify(in)
	if len(open) != 1 {
		t.Fatalf("want one row, got %+v", open)
	}
	return open[0]
}

func TestClassifyForwardToNodeOwned(t *testing.T) {
	r := oneRow(t, OverviewInput{
		External: []External{ext("tcp", 80, "192.168.1.2", 8080, now.Add(-72*time.Hour), now, "open")},
		Listen:   []Listen{selfListen("tcp", 8080, "web", "HTTP")},
		Local:    local("192.168.1.2"),
	})
	if r.Level != LevelLikely || r.Class != ClassExpected || r.Device != SelfAddress || !r.Listening || r.Service != "HTTP" || r.Port != 80 || r.InternalPort != 8080 {
		t.Fatalf("row: %+v", r)
	}
}

func TestClassifyForwardToDeviceListening(t *testing.T) {
	r := oneRow(t, OverviewInput{
		External: []External{ext("tcp", 5000, "192.168.1.50", 5000, now.Add(-72*time.Hour), now, "open")},
		Listen:   []Listen{hostListen("192.168.1.50", 5000, "")},
		Names:    map[string]string{"192.168.1.50": "NAS"},
		Local:    local("192.168.1.2"),
	})
	if r.Level != LevelLikely || r.Class != ClassUnexpected || r.Device != "NAS" || !r.Listening || r.InternalAddr != "192.168.1.50" {
		t.Fatalf("row: %+v", r)
	}
}

func TestClassifyForwardWithoutListener(t *testing.T) {
	r := oneRow(t, OverviewInput{
		External: []External{ext("tcp", 22, "192.168.1.60", 22, now.Add(-72*time.Hour), now, "open")},
		Local:    local("192.168.1.2"),
	})
	if r.Level != LevelUnknown || r.Class != ClassUnexpected || r.Listening || r.Device != "192.168.1.60" || r.Service != "ssh" {
		t.Fatalf("row: %+v", r)
	}
}

func TestClassifyExpectedList(t *testing.T) {
	r := oneRow(t, OverviewInput{
		External: []External{ext("tcp", 5000, "192.168.1.50", 5000, now.Add(-72*time.Hour), now, "open")},
		Listen:   []Listen{hostListen("192.168.1.50", 5000, "")},
		Expected: []Expected{{Proto: "tcp", Port: 5000, Note: "NAS Web"}},
	})
	if r.Class != ClassExpected {
		t.Fatalf("an entry in the expected list must win: %+v", r)
	}
	// Protokoll zaehlt: udp 5000 ist damit nicht erwartet
	r = oneRow(t, OverviewInput{
		External: []External{ext("udp", 5000, "192.168.1.50", 5000, now.Add(-72*time.Hour), now, "open")},
		Expected: []Expected{{Proto: "tcp", Port: 5000}},
	})
	if r.Class != ClassUnexpected {
		t.Fatalf("protocol must match: %+v", r)
	}
}

func TestClassifyOwnedPortOnlyCountsForTheNode(t *testing.T) {
	// Ein Geraet im LAN, dessen Port zufaellig auch bei der Node einen Besitzer hat, macht nichts erwartet
	r := oneRow(t, OverviewInput{
		External: []External{ext("tcp", 8080, "192.168.1.50", 8080, now.Add(-72*time.Hour), now, "open")},
		Listen:   []Listen{selfListen("tcp", 8080, "web", "HTTP"), hostListen("192.168.1.50", 8080, "")},
		Local:    local("192.168.1.2"),
	})
	if r.Class != ClassUnexpected || r.Device == SelfAddress {
		t.Fatalf("row: %+v", r)
	}
}

func TestClassifyUDPOnlyKnownForSelf(t *testing.T) {
	r := oneRow(t, OverviewInput{
		External: []External{ext("udp", 51820, "192.168.1.50", 51820, now.Add(-72*time.Hour), now, "open")},
		Listen:   []Listen{hostListen("192.168.1.50", 51820, "")}, // TCP-Scan: sagt nichts ueber UDP
	})
	if r.Level != LevelUnknown || r.Listening {
		t.Fatalf("row: %+v", r)
	}
	r = oneRow(t, OverviewInput{
		External: []External{ext("udp", 51820, "192.168.1.2", 51820, now.Add(-72*time.Hour), now, "open")},
		Listen:   []Listen{{Address: SelfAddress, Proto: "udp", Port: 51820, State: "open", Owner: "wg", Service: "wireguard"}},
		Local:    local("192.168.1.2"),
	})
	if r.Level != LevelLikely || r.Class != ClassExpected {
		t.Fatalf("udp on the node is known: %+v", r)
	}
}

func TestClassifyNewAndGone(t *testing.T) {
	in := OverviewInput{Now: now, External: []External{
		ext("tcp", 1, "192.168.1.5", 1, now.Add(-23*time.Hour), now, "open"),
		ext("tcp", 2, "192.168.1.5", 2, now.Add(-25*time.Hour), now, "open"),
		ext("tcp", 3, "192.168.1.5", 3, now.Add(-200*time.Hour), now.Add(-6*24*time.Hour), "gone"),
		ext("tcp", 4, "192.168.1.5", 4, now.Add(-200*time.Hour), now.Add(-8*24*time.Hour), "gone"),
		ext("tcp", 5, "192.168.1.5", 5, now.Add(-200*time.Hour), now.Add(-1*time.Hour), "gone"),
	}}
	open, gone := Classify(in)
	if len(open) != 2 || !open[0].New || open[1].New {
		t.Fatalf("new: %+v", open)
	}
	if len(gone) != 2 || gone[0].Port != 5 || gone[1].Port != 3 {
		t.Fatalf("gone must be the last 7 days, newest first: %+v", gone)
	}
}

func TestClassifyBadInternalAddr(t *testing.T) {
	for _, bad := range []string{"", "abc", "999.1.1.1"} {
		r := oneRow(t, OverviewInput{External: []External{ext("tcp", 80, bad, 80, now.Add(-72*time.Hour), now, "open")}, Listen: []Listen{selfListen("tcp", 80, "web", "")}})
		if r.Level != LevelUnknown || r.Listening || r.Class != ClassUnexpected || r.Device != bad {
			t.Errorf("%q: %+v", bad, r)
		}
	}
}

func TestClassifyMappedAddresses(t *testing.T) {
	r := oneRow(t, OverviewInput{
		External: []External{ext("tcp", 80, "::ffff:192.168.1.2", 8080, now.Add(-72*time.Hour), now, "open")},
		Listen:   []Listen{selfListen("tcp", 8080, "web", "HTTP")},
		Local:    local("192.168.1.2"),
	})
	if r.Device != SelfAddress || r.Level != LevelLikely {
		t.Fatalf("4in6 must equal the plain address: %+v", r)
	}
}

func TestClassifyOrder(t *testing.T) {
	open, _ := Classify(OverviewInput{Now: now, External: []External{
		ext("udp", 53, "192.168.1.5", 53, now, now, "open"), ext("tcp", 443, "192.168.1.5", 443, now, now, "open"),
		ext("tcp", 53, "192.168.1.5", 53, now, now, "open"), ext("tcp", 22, "192.168.1.5", 22, now, now, "open"),
	}})
	want := []struct {
		port  int
		proto string
	}{{22, "tcp"}, {53, "tcp"}, {53, "udp"}, {443, "tcp"}}
	for i, w := range want {
		if open[i].Port != w.port || open[i].Proto != w.proto {
			t.Fatalf("order at %d: %+v", i, open)
		}
	}
}

func TestClassifyIgnoresGoneListenRows(t *testing.T) {
	r := oneRow(t, OverviewInput{
		External: []External{ext("tcp", 5000, "192.168.1.50", 5000, now.Add(-72*time.Hour), now, "open")},
		Listen:   []Listen{{Address: "192.168.1.50", Proto: "tcp", Port: 5000, State: "gone"}},
	})
	if r.Listening || r.Level != LevelUnknown {
		t.Fatalf("a gone port is not listening: %+v", r)
	}
}
