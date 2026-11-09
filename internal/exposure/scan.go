package exposure

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// ErrNotAllowed: das Ziel ist kein privates Netz (oder Loopback); es wird nie verbunden.
var ErrNotAllowed = errors.New("exposure: target is not a private address")

// Zustaende eines Ports bei einem Scan.
const (
	StateOpen     = "open"     // Verbindung kam zustande
	StateClosed   = "closed"   // Verbindung abgelehnt: das Geraet antwortet, der Port ist zu
	StateFiltered = "filtered" // Zeitlimit oder anderer Fehler: keine Aussage
)

// cgnat ist 100.64.0.0/10 (Carrier-Grade NAT, bei manchen Heimnetzen als LAN genutzt).
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// ScanAllowed sagt, ob ein Ziel gescannt werden darf: private Bereiche (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7)
// und Loopback. Link-Local, Multicast, unbestimmte, oeffentliche und reservierte Adressen nie.
func ScanAllowed(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() {
		return false
	}
	return a.IsLoopback() || a.IsPrivate() || cgnat.Contains(a)
}

// PortResult ist das Ergebnis fuer einen Port.
type PortResult struct {
	Port  int
	State string
}

// ScanOptions steuern den Scan; Dial ersetzen Tests.
type ScanOptions struct {
	Parallel int
	Timeout  time.Duration
	Dial     func(ctx context.Context, network, address string) (net.Conn, error)
}

// DefaultScanOptions: 16 parallel, 1 Sekunde je Verbindung.
func DefaultScanOptions() ScanOptions {
	var d net.Dialer
	return ScanOptions{Parallel: 16, Timeout: time.Second, Dial: d.DialContext}
}

// ScanHost verbindet sich per TCP mit den Ports eines Geraets. ErrNotAllowed, wenn das Ziel nicht gescannt werden
// darf (dann wird nie verbunden); bricht ctx ab, kommt ctx.Err() zurueck. Das Ergebnis ist nach Port sortiert.
func ScanHost(ctx context.Context, a netip.Addr, ports []int, o ScanOptions) ([]PortResult, error) {
	if !ScanAllowed(a) {
		return nil, ErrNotAllowed
	}
	a = a.Unmap().WithZone("")
	if o.Parallel < 1 {
		o.Parallel = 1
	}
	if o.Timeout <= 0 {
		o.Timeout = time.Second
	}
	if o.Dial == nil {
		o.Dial = DefaultScanOptions().Dial
	}
	out := make([]PortResult, len(ports))
	sem := make(chan struct{}, o.Parallel)
	var wg sync.WaitGroup
loop:
	for i, p := range ports {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break loop
		}
		wg.Add(1)
		go func(i, p int) {
			defer func() { <-sem; wg.Done() }()
			out[i] = PortResult{Port: p, State: probe(ctx, a, p, o)}
		}(i, p)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out, nil
}

// probe verbindet sich mit einem Port und ordnet das Ergebnis ein.
func probe(ctx context.Context, a netip.Addr, port int, o ScanOptions) string {
	cctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	conn, err := o.Dial(cctx, "tcp", net.JoinHostPort(a.String(), strconv.Itoa(port)))
	switch {
	case err == nil:
		_ = conn.Close()
		return StateOpen
	case errors.Is(err, syscall.ECONNREFUSED):
		return StateClosed
	}
	return StateFiltered
}

// Reached: das Geraet hat auf mindestens einem Port geantwortet (offen oder abgelehnt). Nur dann sagt ein Scan etwas
// darueber aus, was dort offen ist; sonst ist das Geraet vermutlich aus.
func Reached(rs []PortResult) bool {
	for _, r := range rs {
		if r.State == StateOpen || r.State == StateClosed {
			return true
		}
	}
	return false
}
