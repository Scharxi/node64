package exposure

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// SSDP-Suche nach dem Router (Internet Gateway Device) per UDP-Multicast. Antworten kommen von beliebigen Geraeten im
// LAN und sind nicht vertrauenswuerdig: nur gueltige Antworten mit sicherer LOCATION (SafeLocation) zaehlen.

const (
	ssdpAddr        = "239.255.255.250:1900"
	ssdpMaxResponse = 8192 // laengere Antworten werden verworfen
	ssdpMaxReplies  = 64   // so viele Antworten werden je Suche gelesen
)

// ssdpTargets sind die gesuchten Geraetetypen.
var ssdpTargets = []string{
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
}

// ssdpRequest baut die Suchanfrage (M-SEARCH) fuer einen Geraetetyp.
func ssdpRequest(st string) []byte {
	return []byte("M-SEARCH * HTTP/1.1\r\nHOST: " + ssdpAddr + "\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: " + st + "\r\n\r\n")
}

// ParseSSDPResponse liest eine Antwort auf die Suche: Statuszeile 200, Kopf LOCATION (Name ohne Beachtung der
// Schreibweise). ok = false bei allem anderen, auch bei Antworten ueber ssdpMaxResponse Bytes.
func ParseSSDPResponse(b []byte) (location string, ok bool) {
	if len(b) == 0 || len(b) > ssdpMaxResponse {
		return "", false
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	if !sc.Scan() {
		return "", false
	}
	status := strings.Fields(sc.Text())
	if len(status) < 2 || !strings.HasPrefix(status[0], "HTTP/1.") || status[1] != "200" {
		return "", false
	}
	for sc.Scan() {
		name, value, found := strings.Cut(sc.Text(), ":")
		if found && strings.EqualFold(strings.TrimSpace(name), "location") {
			value = strings.TrimSpace(value)
			return value, value != ""
		}
	}
	return "", false
}

// SSDPReply ist eine Antwort auf die Suche mit der Adresse des Absenders.
type SSDPReply struct {
	Data []byte
	From netip.Addr
}

// SSDPOptions steuern die Suche; Exchange ersetzen Tests (sendet die Anfragen, liefert die Antworten bis wait).
type SSDPOptions struct {
	Wait     time.Duration
	Exchange func(ctx context.Context, payloads [][]byte, wait time.Duration) ([]SSDPReply, error)
}

// DefaultSSDPOptions: 2 Sekunden warten, echter UDP-Multicast.
func DefaultSSDPOptions() SSDPOptions {
	return SSDPOptions{Wait: 2 * time.Second, Exchange: multicastExchange}
}

// multicastExchange sendet die Anfragen an die Multicast-Gruppe und sammelt die Antworten bis wait.
func multicastExchange(ctx context.Context, payloads [][]byte, wait time.Duration) ([]SSDPReply, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	dst, err := net.ResolveUDPAddr("udp4", ssdpAddr)
	if err != nil {
		return nil, err
	}
	for _, p := range payloads {
		if _, err := conn.WriteToUDP(p, dst); err != nil {
			return nil, err
		}
	}
	deadline := time.Now().Add(wait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetReadDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	var out []SSDPReply
	buf := make([]byte, ssdpMaxResponse+1)
	for len(out) < ssdpMaxReplies {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // Zeitlimit oder Abbruch: was bis dahin kam, zaehlt
		}
		var src netip.Addr
		if from != nil {
			if a, ok := netip.AddrFromSlice(from.IP); ok {
				src = a.Unmap()
			}
		}
		out = append(out, SSDPReply{Data: append([]byte(nil), buf[:n]...), From: src})
	}
	return out, nil
}

// SearchGateways sucht Router im LAN und liefert die Beschreibungs-Adressen ohne Duplikate, sortiert. Antworten ohne
// gueltige oder ohne sichere LOCATION werden verworfen, ebenso Antworten, deren LOCATION nicht auf den Absender zeigt:
// so gibt sich kein Geraet im LAN als Router eines anderen aus.
func SearchGateways(ctx context.Context, o SSDPOptions) ([]string, error) {
	if o.Exchange == nil {
		o.Exchange = multicastExchange
	}
	if o.Wait <= 0 {
		o.Wait = 2 * time.Second
	}
	payloads := make([][]byte, len(ssdpTargets))
	for i, st := range ssdpTargets {
		payloads[i] = ssdpRequest(st)
	}
	replies, err := o.Exchange(ctx, payloads, o.Wait)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range replies {
		loc, ok := ParseSSDPResponse(r.Data)
		if !ok || seen[loc] {
			continue
		}
		u, err := SafeLocation(loc)
		if err != nil {
			continue
		}
		if host, herr := netip.ParseAddr(u.Hostname()); herr != nil || !r.From.IsValid() || host.Unmap() != r.From.Unmap() {
			continue
		}
		seen[loc] = true
		out = append(out, loc)
	}
	sort.Strings(out)
	return out, nil
}
