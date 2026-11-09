package ipam

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func TestStatusAt(t *testing.T) {
	seen := t0.Add(-time.Hour)
	cases := []struct {
		name string
		a    Address
		want Status
	}{
		{"reserved and offline", Address{Reserved: true}, StatusReserved},
		{"reserved and seen", Address{Reserved: true, LastSeen: seen}, StatusUsed},
		{"seen without anything is new", Address{LastSeen: seen}, StatusNew},
		{"seen with source name", Address{LastSeen: seen, SourceName: "nas"}, StatusUsed},
		{"seen with manual name", Address{LastSeen: seen, Name: "nas"}, StatusUsed},
		{"seen and ignored", Address{LastSeen: seen, Ignored: true}, StatusUsed},
		{"seen and acknowledged", Address{LastSeen: seen, Acknowledged: true}, StatusUsed},
		{"seen and auto known", Address{LastSeen: seen, AutoKnown: true}, StatusUsed},
		{"never seen", Address{}, StatusOffline},
		{"exactly 24h", Address{LastSeen: t0.Add(-seenWindow)}, StatusNew},
		{"unknown device stays new after 24h", Address{LastSeen: t0.Add(-seenWindow - time.Second)}, StatusNew},
		{"unknown device stays new for days", Address{LastSeen: t0.Add(-5 * 24 * time.Hour)}, StatusNew},
		{"acknowledged and long gone", Address{Acknowledged: true, LastSeen: t0.Add(-5 * 24 * time.Hour)}, StatusOffline},
		{"ignored and long gone", Address{Ignored: true, LastSeen: t0.Add(-5 * 24 * time.Hour)}, StatusOffline},
		{"auto known and long gone", Address{AutoKnown: true, LastSeen: t0.Add(-5 * 24 * time.Hour)}, StatusOffline},
		{"by hand and never seen", Address{Name: "x", Acknowledged: true}, StatusOffline},
		{"named but long gone", Address{Name: "x", LastSeen: t0.Add(-72 * time.Hour)}, StatusOffline},
	}
	for _, c := range cases {
		if got := c.a.StatusAt(t0); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestConflictAt(t *testing.T) {
	seen := t0.Add(-time.Minute)
	cases := []struct {
		name string
		a    Address
		want bool
	}{
		{"other mac seen", Address{ReservedMAC: "aa:aa:aa:aa:aa:aa", MAC: "bb:bb:bb:bb:bb:bb", LastSeen: seen}, true},
		{"same mac", Address{ReservedMAC: "aa:aa:aa:aa:aa:aa", MAC: "aa:aa:aa:aa:aa:aa", LastSeen: seen}, false},
		{"no reserved mac", Address{MAC: "bb:bb:bb:bb:bb:bb", LastSeen: seen}, false},
		{"no observed mac", Address{ReservedMAC: "aa:aa:aa:aa:aa:aa", LastSeen: seen}, false},
		{"not seen anymore", Address{ReservedMAC: "aa:aa:aa:aa:aa:aa", MAC: "bb:bb:bb:bb:bb:bb", LastSeen: t0.Add(-48 * time.Hour)}, false},
	}
	for _, c := range cases {
		if got := c.a.ConflictAt(t0); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDisplayName(t *testing.T) {
	if got := (Address{Name: "hand", SourceName: "quelle"}).DisplayName(); got != "hand" {
		t.Fatalf("manual wins: %q", got)
	}
	if got := (Address{SourceName: "quelle"}).DisplayName(); got != "quelle" {
		t.Fatalf("source name: %q", got)
	}
	_ = netip.Addr{}
}

func TestNormalizeMAC(t *testing.T) {
	for in, want := range map[string]string{
		"AA-BB-CC-DD-EE-FF":    "aa:bb:cc:dd:ee:ff",
		"aabb.ccdd.eeff":       "aa:bb:cc:dd:ee:ff",
		"  AA:bb:CC:dd:EE:ff ": "aa:bb:cc:dd:ee:ff",
		"":                     "",
	} {
		got, err := NormalizeMAC(in)
		if err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "xyz", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00:11"} {
		if _, err := NormalizeMAC(in); !errors.Is(err, ErrInvalidMAC) {
			t.Errorf("%q: err %v, want ErrInvalidMAC", in, err)
		}
	}
}

func TestNormalizeLabel(t *testing.T) {
	if got, err := NormalizeLabel("  Drucker Flur  "); err != nil || got != "Drucker Flur" {
		t.Fatalf("trim: %q %v", got, err)
	}
	if got, err := NormalizeLabel(strings.Repeat("a", 253)); err != nil || len(got) != 253 {
		t.Fatalf("253: %v", err)
	}
	if _, err := NormalizeLabel(strings.Repeat("a", 254)); !errors.Is(err, ErrInvalidLabel) {
		t.Fatalf("254: %v", err)
	}
	for _, in := range []string{"a\x00b", "a\nb", "a\tb"} {
		if _, err := NormalizeLabel(in); !errors.Is(err, ErrInvalidLabel) {
			t.Errorf("%q: %v", in, err)
		}
	}
	// HTML bleibt erlaubt: die Vorlage escaped
	if got, err := NormalizeLabel("<script>"); err != nil || got != "<script>" {
		t.Fatalf("html: %q %v", got, err)
	}
	// 253 Zeichen, nicht Bytes
	if _, err := NormalizeLabel(strings.Repeat("ä", 253)); err != nil {
		t.Fatalf("umlauts: %v", err)
	}
}
