package exposure

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Schluessel in den Einstellungen des Kerns.
const (
	setInterval = "exposure.interval"     // Stunden zwischen zwei LAN-Scans
	setPorts    = "exposure.ports"        // eigene Ports, durch Komma getrennt
	setSubnets  = "exposure.scan_subnets" // IPAM-Subnetze, die gescannt werden (JSON-Liste der IDs)
	setLastScan = "exposure.last_scan"    // Zeitpunkt des letzten Scans (RFC 3339)
	setUPnP     = "exposure.upnp"         // Router per UPnP fragen ("1" = ja)
	setUPnPURL  = "exposure.upnp_url"     // Beschreibungs-Adresse des Routers von Hand (leer = suchen)
)

var (
	ErrInvalidInterval  = errors.New("exposure: invalid interval")
	ErrUnknownSubnet    = errors.New("exposure: unknown subnet")
	ErrSubnetNotPrivate = errors.New("exposure: only private networks can be scanned")
)

// IntervalOptions sind die waehlbaren Abstaende des LAN-Scans in Stunden (der erste Wert nach 24 ist der Standard).
var IntervalOptions = []int{1, 6, 24, 168}

const defaultInterval = 24

// SubnetRef und HostRef sind die Sicht auf IPAM (main.go speist sie ein, das Modul kennt IPAM nicht).
type SubnetRef struct {
	ID   int64
	Name string
	CIDR netip.Prefix
}

type HostRef struct {
	IP   netip.Addr
	Name string
}

// SetSubnets und SetHosts binden IPAM an. Fehler oder nil heisst: IPAM ist nicht verfuegbar, der Scan ueberspringt still.
func (m *Module) SetSubnets(f func(ctx context.Context) ([]SubnetRef, error)) { m.subnets = f }

func (m *Module) SetHosts(f func(ctx context.Context, subnetID int64) ([]HostRef, error)) {
	m.hosts = f
}

// Settings sind die Einstellungen des Moduls.
type Settings struct {
	IntervalHours int
	Ports         []int   // eigene Ports (zusaetzlich zur Standardliste)
	Subnets       []int64 // IPAM-Subnetze, die gescannt werden
	UPnP          bool    // Router per UPnP nach Weiterleitungen fragen (Standard aus)
	UPnPURL       string  // Beschreibungs-Adresse des Routers von Hand; leer = per SSDP suchen
}

// LoadSettings liest die Einstellungen; Ungueltiges faellt auf den Standard zurueck.
func (m *Module) LoadSettings(ctx context.Context) Settings {
	s := Settings{IntervalHours: defaultInterval}
	if n, err := strconv.Atoi(m.core.SettingOr(ctx, setInterval, "")); err == nil && slices.Contains(IntervalOptions, n) {
		s.IntervalHours = n
	}
	if ports, err := ParsePorts(m.core.SettingOr(ctx, setPorts, "")); err == nil {
		s.Ports = ports
	}
	if raw := m.core.SettingOr(ctx, setSubnets, ""); raw != "" {
		_ = json.Unmarshal([]byte(raw), &s.Subnets)
	}
	s.UPnP = m.core.SettingOr(ctx, setUPnP, "") == "1"
	s.UPnPURL = m.core.SettingOr(ctx, setUPnPURL, "")
	return s
}

// SaveSettings prueft und speichert: Intervall aus IntervalOptions, Ports ueber ScanPorts, Subnetze muessen in IPAM
// vorhanden sein (ist IPAM nicht erreichbar, lassen sie sich nicht pruefen und werden abgelehnt).
func (m *Module) SaveSettings(ctx context.Context, s Settings) error {
	if !slices.Contains(IntervalOptions, s.IntervalHours) {
		return ErrInvalidInterval
	}
	if _, err := ScanPorts(s.Ports); err != nil {
		return err
	}
	if s.UPnPURL != "" {
		if _, err := SafeLocation(s.UPnPURL); err != nil {
			return err
		}
	}
	if len(s.Subnets) > 0 {
		known := map[int64]SubnetRef{}
		if m.subnets != nil {
			if subs, err := m.subnets(ctx); err == nil {
				for _, sub := range subs {
					known[sub.ID] = sub
				}
			}
		}
		for _, id := range s.Subnets {
			sub, ok := known[id]
			if !ok {
				return ErrUnknownSubnet
			}
			if !ScanAllowed(sub.CIDR.Addr()) { // oeffentliche Netze lassen sich nicht scannen: nicht still ins Leere laufen
				return ErrSubnetNotPrivate
			}
		}
	}
	return m.saveRaw(ctx, s)
}

// saveRaw speichert ohne Pruefung gegen IPAM (Eingaben sind sortiert und ohne Duplikate).
func (m *Module) saveRaw(ctx context.Context, s Settings) error {
	ports := slices.Clone(s.Ports)
	sort.Ints(ports)
	ports = slices.Compact(ports)
	text := make([]string, len(ports))
	for i, p := range ports {
		text[i] = strconv.Itoa(p)
	}
	subs := slices.Clone(s.Subnets)
	slices.Sort(subs)
	subs = slices.Compact(subs)
	raw, err := json.Marshal(subs)
	if err != nil {
		return err
	}
	if subs == nil {
		raw = []byte("[]")
	}
	upnp := "0"
	if s.UPnP {
		upnp = "1"
	}
	for k, v := range map[string]string{setInterval: strconv.Itoa(s.IntervalHours), setPorts: strings.Join(text, ","), setSubnets: string(raw),
		setUPnP: upnp, setUPnPURL: s.UPnPURL} {
		if err := m.core.SetSetting(ctx, k, v); err != nil {
			return err
		}
	}
	return nil
}
