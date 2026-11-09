package exposure

import (
	"errors"
	"reflect"
	"strconv"
	"testing"
)

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("22, 80\n8000-8002 22")
	if err != nil || !reflect.DeepEqual(got, []int{22, 80, 8000, 8001, 8002}) {
		t.Fatalf("parse: %v %v", got, err)
	}
	if got, err := ParsePorts("22,,80"); err != nil || !reflect.DeepEqual(got, []int{22, 80}) {
		t.Fatalf("empty element tolerated: %v %v", got, err)
	}
	if got, err := ParsePorts("  "); err != nil || len(got) != 0 {
		t.Fatalf("blank: %v %v", got, err)
	}
	for _, bad := range []string{"0", "65536", "abc", "10-5", "22,x", "-5", "80-", "1-2-3", "-1"} {
		if _, err := ParsePorts(bad); !errors.Is(err, ErrInvalidPorts) {
			t.Errorf("%q: err %v, want ErrInvalidPorts", bad, err)
		}
	}
	// riesige Bereiche duerfen nichts allozieren: sofort abgelehnt
	if _, err := ParsePorts("1-65535"); !errors.Is(err, ErrTooManyPorts) {
		t.Errorf("huge range: %v", err)
	}
}

func TestScanPortsLimit(t *testing.T) {
	for _, p := range []int{22, 80, 443, 445, 3389, 5900, 1883, 8080, 8443} {
		found := false
		for _, d := range defaultPorts {
			found = found || d == p
		}
		if !found {
			t.Errorf("default list misses %d", p)
		}
	}
	if len(defaultPorts) < 80 || len(defaultPorts) >= maxPorts {
		t.Fatalf("default list size %d", len(defaultPorts))
	}
	seen := map[int]bool{}
	for _, p := range defaultPorts {
		if p < 1 || p > 65535 || seen[p] {
			t.Fatalf("default list has invalid or duplicate port %d", p)
		}
		seen[p] = true
	}
	// eigene Ports, die schon in der Standardliste stehen, zaehlen nicht doppelt
	got, err := ScanPorts([]int{22, 80, 22})
	if err != nil || len(got) != len(defaultPorts) {
		t.Fatalf("custom duplicates: %d vs %d %v", len(got), len(defaultPorts), err)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("not sorted/unique at %d: %v %v", i, got[i-1], got[i])
		}
	}
	// neue eigene Ports kommen dazu
	got, err = ScanPorts([]int{40001, 40002})
	if err != nil || len(got) != len(defaultPorts)+2 {
		t.Fatalf("custom added: %d %v", len(got), err)
	}
	// mehr als maxPorts insgesamt
	var many []int
	for p := 40000; p < 40000+100; p++ {
		many = append(many, p)
	}
	if _, err := ScanPorts(many); !errors.Is(err, ErrTooManyPorts) {
		t.Fatalf("100 custom ports: %v", err)
	}
	if _, err := ScanPorts([]int{0}); !errors.Is(err, ErrInvalidPorts) {
		t.Fatalf("port 0: %v", err)
	}
	if _, err := ScanPorts([]int{70000}); !errors.Is(err, ErrInvalidPorts) {
		t.Fatalf("port 70000: %v", err)
	}
}

func TestServiceName(t *testing.T) {
	for _, c := range []struct {
		proto string
		port  int
		want  string
	}{{"tcp", 22, "ssh"}, {"tcp", 443, "https"}, {"tcp", 80, "http"}, {"udp", 53, "dns"}, {"tcp", 65000, ""}} {
		if got := ServiceName(c.proto, c.port); got != c.want {
			t.Errorf("%s/%s: %q, want %q", c.proto, strconv.Itoa(c.port), got, c.want)
		}
	}
}
