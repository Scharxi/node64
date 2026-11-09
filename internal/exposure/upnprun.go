package exposure

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// upnpEvery: so selten fragt die Schleife den Router (SSDP sendet Multicast). "Jetzt pruefen" fragt immer.
var upnpEvery = time.Hour

// SetGateways ersetzt die Suche nach dem Router (Standard: SSDP-Multicast).
func (m *Module) SetGateways(f func(ctx context.Context) ([]string, error)) { m.gateways = f }

// SetUPnPOptions setzt die Grenzen der UPnP-Abfrage (Tests setzen kurze Zeitlimits).
func (m *Module) SetUPnPOptions(o UPnPOptions) { m.upnpOpts = o }

// SetLocalAddrs ersetzt die Quelle der eigenen Adressen (Standard: die Adressen der Netzwerk-Schnittstellen).
func (m *Module) SetLocalAddrs(f func() []netip.Addr) { m.localAddrs = f }

// defaultLocalAddrs liefert die Adressen der Schnittstellen (entpackt, ohne Duplikate).
func defaultLocalAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}

func (m *Module) setUPnPErr(text string) {
	m.st.mu.Lock()
	m.st.upnpErr = text
	m.st.mu.Unlock()
}

// upnpDue: UPnP ist eingeschaltet und der letzte Versuch liegt mindestens upnpEvery zurueck (oder es gab noch keinen).
func (m *Module) upnpDue(ctx context.Context, now time.Time) bool {
	if !m.LoadSettings(ctx).UPnP {
		return false
	}
	m.st.mu.Lock()
	tried := m.st.upnpTried
	m.st.mu.Unlock()
	return tried.IsZero() || now.Sub(tried) >= upnpEvery
}

// readUPnP fragt den Router nach seinen Weiterleitungen und speichert sie. Nichts zu finden oder ein Fehler des Routers
// ist ein Zustand der Seite (UPnPErr), kein Fehler des Laufs, und laesst alle bekannten Weiterleitungen, wie sie sind:
// nur eine erfolgreiche Abfrage ohne Abschneiden darf Eintraege auf "weg" setzen.
func (m *Module) readUPnP(ctx context.Context, now time.Time) error {
	s := m.LoadSettings(ctx)
	if !s.UPnP {
		return nil
	}
	m.st.mu.Lock()
	m.st.upnpTried = now
	m.st.mu.Unlock()
	locations := []string{s.UPnPURL}
	if s.UPnPURL == "" {
		var err error
		if locations, err = m.gateways(ctx); err != nil {
			m.setUPnPErr(err.Error())
			return nil
		}
	}
	if len(locations) == 0 {
		m.setUPnPErr("no gateway found")
		return nil
	}
	var info RouterInfo
	var lastErr error
	found, used := false, ""
	for _, loc := range locations {
		if info, lastErr = QueryRouter(ctx, loc, m.upnpOpts); lastErr == nil {
			found, used = true, loc
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if !found {
		m.setUPnPErr(lastErr.Error())
		return nil
	}
	rows := make([]External, 0, len(info.Mappings))
	for _, mp := range info.Mappings {
		rows = append(rows, External{Proto: mp.Proto, Port: mp.ExternalPort, InternalAddr: mp.InternalAddr.String(), InternalPort: mp.InternalPort, Description: mp.Description})
	}
	if err := m.recordExternalMode(ctx, now, EvidenceUPnP, rows, !info.Truncated); err != nil {
		return err
	}
	ext := ""
	if info.ExternalIP.IsValid() {
		ext = info.ExternalIP.String()
	}
	m.st.mu.Lock()
	m.st.upnpAt, m.st.upnpErr, m.st.externalIP, m.st.mappings, m.st.upnpTruncated = now, "", ext, len(rows), info.Truncated
	m.st.upnpLocation, m.st.upnpGateways = used, len(locations)
	m.st.mu.Unlock()
	return nil
}
