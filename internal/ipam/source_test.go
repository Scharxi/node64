package ipam

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/dns64/groups"
)

func TestPollOnce(t *testing.T) {
	m, v4, _ := ingestEnv(t)
	ctx := context.Background()
	m.AddSource(FuncSource{N: "good", Fn: func(context.Context) ([]Observation, error) {
		return []Observation{obs("192.168.1.5", "", "nas", SourceDNS64), obs("10.9.9.9", "", "", SourceDNS64)}, nil
	}})
	m.AddSource(FuncSource{N: "bad", Fn: func(context.Context) ([]Observation, error) { return nil, errors.New("down") }})
	m.pollOnce(ctx, t0)

	if a := addrOf(t, m, v4, "192.168.1.5"); a.SourceName != "nas" {
		t.Fatalf("good source stored despite the failing one: %+v", a)
	}
	st := m.SourceStatus()
	if len(st) != 2 || st[0].Name != "good" || st[0].Count != 2 || st[0].Err != "" || !st[0].LastOK.Equal(t0) {
		t.Fatalf("good status: %+v", st)
	}
	if st[1].Name != "bad" || st[1].Err != "down" {
		t.Fatalf("bad status: %+v", st[1])
	}
	if m.Outside() != 1 {
		t.Fatalf("outside: %d", m.Outside())
	}
}

func TestNeighborSourceSkipsStale(t *testing.T) {
	old := neighborFn
	t.Cleanup(func() { neighborFn = old })
	neighborFn = func() (map[netip.Addr]groups.Neighbor, error) {
		return map[netip.Addr]groups.Neighbor{
			netip.MustParseAddr("192.168.1.1"): {MAC: "aa:bb:cc:00:00:01"},
			netip.MustParseAddr("192.168.1.2"): {MAC: "aa:bb:cc:00:00:02", Stale: true},
		}, nil
	}
	got, err := NeighborSource().Collect(context.Background())
	if err != nil || len(got) != 1 || got[0].IP.String() != "192.168.1.1" || got[0].MAC != "aa:bb:cc:00:00:01" || got[0].Source != SourceNeighbor {
		t.Fatalf("collect: %+v %v", got, err)
	}
	neighborFn = func() (map[netip.Addr]groups.Neighbor, error) { return nil, errors.New("netlink") }
	if _, err := NeighborSource().Collect(context.Background()); err == nil {
		t.Fatal("error must pass through")
	}
}

func TestStartPollsAndStops(t *testing.T) {
	old := pollEvery
	pollEvery = 10 * time.Millisecond
	t.Cleanup(func() { pollEvery = old })
	m := newTestModule(t)
	var calls atomic.Int64
	m.AddSource(FuncSource{N: "count", Fn: func(context.Context) ([]Observation, error) { calls.Add(1); return nil, nil }})
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if calls.Load() < 3 {
		t.Fatalf("source polled %d times, want at least 3", calls.Load())
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := calls.Load()
	time.Sleep(60 * time.Millisecond)
	if calls.Load() != after {
		t.Fatalf("polling continued after Stop: %d -> %d", after, calls.Load())
	}
}
