package exposure

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestScanAllowed(t *testing.T) {
	for _, ok := range []string{"192.168.1.5", "10.0.0.1", "172.16.0.1", "172.31.255.254", "100.64.0.1", "fd00:64::1", "127.0.0.1", "::1", "::ffff:192.168.1.5"} {
		if !ScanAllowed(netip.MustParseAddr(ok)) {
			t.Errorf("%s must be allowed", ok)
		}
	}
	for _, bad := range []string{"8.8.8.8", "2001:4860:4860::8888", "169.254.1.1", "fe80::1", "fe80::1%eth0", "224.0.0.1", "ff02::1",
		"255.255.255.255", "0.0.0.0", "::", "172.32.0.1", "100.128.0.1", "192.0.2.1"} {
		if ScanAllowed(netip.MustParseAddr(bad)) {
			t.Errorf("%s must be refused", bad)
		}
	}
	if ScanAllowed(netip.Addr{}) {
		t.Error("invalid address must be refused")
	}
}

func listenTCP(t *testing.T) (*net.TCPListener, int) {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l, l.Addr().(*net.TCPAddr).Port
}

func TestScanHostFindsOpenAndClosed(t *testing.T) {
	_, open := listenTCP(t)
	closedL, closed := listenTCP(t)
	closedL.Close() // danach lauscht dort niemand mehr
	rs, err := ScanHost(context.Background(), netip.MustParseAddr("127.0.0.1"), []int{open, closed}, DefaultScanOptions())
	if err != nil || len(rs) != 2 {
		t.Fatalf("scan: %v %v", rs, err)
	}
	state := map[int]string{}
	for _, r := range rs {
		state[r.Port] = r.State
	}
	if state[open] != StateOpen || state[closed] != StateClosed {
		t.Fatalf("states: %v (open %d, closed %d)", state, open, closed)
	}
	if !Reached(rs) {
		t.Fatal("host answered, must count as reached")
	}
}

func TestScanHostRefusesPublic(t *testing.T) {
	var calls atomic.Int64
	o := DefaultScanOptions()
	o.Dial = func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("must not dial")
	}
	for _, a := range []string{"8.8.8.8", "169.254.1.1", "fe80::1", "224.0.0.1"} {
		if _, err := ScanHost(context.Background(), netip.MustParseAddr(a), []int{22, 80}, o); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s: err %v, want ErrNotAllowed", a, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("refused addresses must never be dialled, got %d calls", calls.Load())
	}
}

func TestScanHostTimeoutIsFiltered(t *testing.T) {
	o := DefaultScanOptions()
	o.Timeout = 20 * time.Millisecond
	o.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	rs, err := ScanHost(context.Background(), netip.MustParseAddr("192.168.1.5"), []int{22, 80}, o)
	if err != nil || len(rs) != 2 || rs[0].State != StateFiltered || rs[1].State != StateFiltered {
		t.Fatalf("timeout: %v %v", rs, err)
	}
	if Reached(rs) {
		t.Fatal("all filtered: host did not answer, must not count as reached")
	}
}

func TestScanHostParallelLimit(t *testing.T) {
	var active, peak atomic.Int64
	o := DefaultScanOptions()
	o.Parallel = 4
	o.Dial = func(context.Context, string, string) (net.Conn, error) {
		n := active.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		active.Add(-1)
		return nil, syscall.ECONNREFUSED
	}
	ports := make([]int, 40)
	for i := range ports {
		ports[i] = 1000 + i
	}
	rs, err := ScanHost(context.Background(), netip.MustParseAddr("10.0.0.5"), ports, o)
	if err != nil || len(rs) != 40 {
		t.Fatalf("scan: %d %v", len(rs), err)
	}
	if peak.Load() > 4 || peak.Load() < 2 {
		t.Fatalf("parallelism peak %d, want 2..4", peak.Load())
	}
	for i := 1; i < len(rs); i++ {
		if rs[i-1].Port >= rs[i].Port {
			t.Fatalf("not sorted: %v", rs)
		}
	}
}

func TestScanHostCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	o := DefaultScanOptions()
	o.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	if _, err := ScanHost(ctx, netip.MustParseAddr("10.0.0.5"), []int{22, 80, 443}, o); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

func TestReached(t *testing.T) {
	if Reached(nil) {
		t.Error("nil")
	}
	if !Reached([]PortResult{{22, StateFiltered}, {80, StateClosed}}) {
		t.Error("a refused connection means the host answered")
	}
	if !Reached([]PortResult{{22, StateOpen}}) {
		t.Error("open")
	}
	if Reached([]PortResult{{22, StateFiltered}}) {
		t.Error("filtered only")
	}
}
