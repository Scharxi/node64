package exposure

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/module"
)

//go:embed templates
var templateFS embed.FS

// Templates liefert die Seiten des Moduls (module.Templater).
func (m *Module) Templates() fs.FS {
	sub, _ := fs.Sub(templateFS, "templates")
	return sub
}

// uiRoutes registriert die Seite und ihre Formulare.
func (m *Module) uiRoutes(mux *http.ServeMux, g module.Guards) {
	page := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /exposure", page(m.pageOverview))
	mux.Handle("POST /exposure/settings", page(m.pageSettings))
	mux.Handle("POST /exposure/scan", page(m.pageScan))
	mux.Handle("POST /exposure/expected", page(m.pageExpectedAdd))
	mux.Handle("POST /exposure/expected/delete", page(m.pageExpectedDelete))
}

// hostView ist ein Geraet mit offenen Ports.
type hostView struct {
	Address  string
	Name     string
	Ports    []Listen
	LastSeen time.Time // letzte Sichtung eines offenen Ports
	Stale    bool      // IPAM fuehrt das Geraet nicht mehr als gesehen: die Ports stammen vom letzten Scan
}

// subnetView ist ein eingeschaltetes Subnetz mit seinen Geraeten.
type subnetView struct {
	Ref   SubnetRef
	Hosts []hostView
}

// subnetChoice ist ein Subnetz in der Auswahl der Einstellungen.
type subnetChoice struct {
	Ref     SubnetRef
	Enabled bool
	Private bool // nur private Netze lassen sich scannen
}

type overviewData struct {
	Self      []Listen
	SelfKnown bool
	Status    RunStatus
	Subnets   []subnetView
	Choices   []subnetChoice
	IPAM      bool // IPAM liefert Subnetze
	Settings  Settings
	PortsText string
	Intervals []int
	Reach     []OverviewRow // Weiterleitungen des Routers, zusammengefuehrt mit der Innen-Sicht
	Gone      []External    // kuerzlich weggefallene Weiterleitungen
	Expecteds []Expected
	History   []Event // letzte Aenderungen
	KeepDays  []int
}

func (m *Module) pageOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := m.Listening(ctx, "")
	if err != nil {
		m.log.Error("exposure page", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	d := overviewData{Status: m.Status(), Settings: m.LoadSettings(ctx), Intervals: IntervalOptions}
	d.SelfKnown = d.Status.SelfKnown
	d.PortsText = joinPorts(d.Settings.Ports)
	enabled := map[int64]bool{}
	for _, id := range d.Settings.Subnets {
		enabled[id] = true
	}
	var subs []SubnetRef
	if m.subnets != nil {
		if got, err := m.subnets(ctx); err == nil {
			subs, d.IPAM = got, true
		}
	}
	for _, s := range subs {
		d.Choices = append(d.Choices, subnetChoice{Ref: s, Enabled: enabled[s.ID], Private: ScanAllowed(s.CIDR.Addr())})
		if !enabled[s.ID] {
			continue
		}
		d.Subnets = append(d.Subnets, m.subnetView(ctx, s, rows))
	}
	for _, l := range rows {
		if l.Address == SelfAddress && l.State == "open" {
			d.Self = append(d.Self, l)
		}
	}
	d.Reach, d.Gone, d.Expecteds = m.reachOverview(ctx, rows, subs)
	d.History, _ = m.Events(ctx, 50)
	d.KeepDays = KeepDaysOptions
	m.g.Render(w, r, http.StatusOK, Name+"/overview", "exposure.title", d)
}

// reachOverview fuehrt die Weiterleitungen des Routers mit der Innen-Sicht (rows) und den Erwartungen zusammen.
func (m *Module) reachOverview(ctx context.Context, rows []Listen, subs []SubnetRef) ([]OverviewRow, []External, []Expected) {
	ext, _ := m.Externals(ctx)
	exp, _ := m.Expecteds(ctx)
	var local []netip.Addr
	if m.localAddrs != nil {
		local = m.localAddrs()
	}
	open, gone := Classify(OverviewInput{External: ext, Listen: rows, Expected: exp, Local: local, Names: m.ipamNames(ctx, subs), Now: time.Now().UTC()})
	return open, gone, exp
}

// ipamNames liefert die Namen der Geraete aus IPAM je Adresse (leer, wenn IPAM nicht antwortet).
func (m *Module) ipamNames(ctx context.Context, subs []SubnetRef) map[string]string {
	names := map[string]string{}
	if m.hosts == nil {
		return names
	}
	for _, s := range subs {
		if hs, err := m.hosts(ctx, s.ID); err == nil {
			for _, h := range hs {
				if h.Name != "" {
					names[h.IP.Unmap().String()] = h.Name
				}
			}
		}
	}
	return names
}

// subnetView sammelt die Geraete eines Subnetzes mit offenen Ports (Namen aus IPAM).
func (m *Module) subnetView(ctx context.Context, s SubnetRef, rows []Listen) subnetView {
	v := subnetView{Ref: s}
	names := map[string]string{}
	hostsKnown := false // IPAM hat geantwortet: nur dann laesst sich "nicht mehr gesehen" sagen
	if m.hosts != nil {
		if hs, err := m.hosts(ctx, s.ID); err == nil {
			hostsKnown = true
			for _, h := range hs {
				names[h.IP.Unmap().String()] = h.Name
			}
		}
	}
	byAddr := map[string][]Listen{}
	for _, l := range rows {
		ip, err := netip.ParseAddr(l.Address)
		if l.Address == SelfAddress || err != nil || l.State != "open" || !s.CIDR.Contains(ip) {
			continue
		}
		byAddr[l.Address] = append(byAddr[l.Address], l)
	}
	for addr, ports := range byAddr {
		hv := hostView{Address: addr, Name: names[addr], Ports: ports}
		for _, p := range ports {
			if p.LastSeen.After(hv.LastSeen) {
				hv.LastSeen = p.LastSeen
			}
		}
		_, seen := names[addr]
		hv.Stale = hostsKnown && !seen
		v.Hosts = append(v.Hosts, hv)
	}
	sort.Slice(v.Hosts, func(i, j int) bool {
		a, _ := netip.ParseAddr(v.Hosts[i].Address)
		b, _ := netip.ParseAddr(v.Hosts[j].Address)
		return a.Compare(b) < 0
	})
	return v
}

func joinPorts(ps []int) string {
	out := ""
	for i, p := range ps {
		if i > 0 {
			out += ", "
		}
		out += strconv.Itoa(p)
	}
	return out
}

func (m *Module) back(w http.ResponseWriter, r *http.Request, kind, text string) {
	if text != "" {
		m.g.Flash(w, r, kind, text)
	}
	http.Redirect(w, r, "/exposure", http.StatusSeeOther)
}

func (m *Module) audit(r *http.Request, action, target, details string) {
	if m.g.Audit != nil {
		m.g.Audit(r, action, target, details)
	}
}

// errText uebersetzt einen Fehler des Moduls in die Sprache des Aufrufers.
func (m *Module) errText(r *http.Request, err error) string {
	keys := []struct {
		err error
		key string
	}{
		{ErrInvalidPorts, "exposure.err.ports"}, {ErrTooManyPorts, "exposure.err.too_many"}, {ErrInvalidInterval, "exposure.err.interval"},
		{ErrUnknownSubnet, "exposure.err.subnet"}, {ErrSubnetNotPrivate, "exposure.err.not_private"}, {ErrBusy, "exposure.err.busy"},
		{ErrInvalidExpected, "exposure.err.invalid_expected"}, {ErrInvalidKeepDays, "exposure.err.keep_days"}, {ErrUnsafeURL, "exposure.err.unsafe_url"}, {ErrNotFound, "exposure.err.not_found"},
	}
	for _, k := range keys {
		if errors.Is(err, k.err) {
			return m.g.T(r, k.key)
		}
	}
	m.log.Error("exposure", "err", err)
	return m.g.T(r, "common.error")
}

func (m *Module) pageSettings(w http.ResponseWriter, r *http.Request) {
	hours, _ := strconv.Atoi(r.PostFormValue("interval"))
	s := Settings{IntervalHours: hours}
	ports, err := ParsePorts(r.PostFormValue("ports"))
	if err != nil {
		m.back(w, r, "danger", m.errText(r, err))
		return
	}
	s.Ports = ports
	s.KeepDays = m.LoadSettings(r.Context()).KeepDays // ohne Feld bleibt der Wert (sonst wuerde ein altes Formular "unbegrenzt" setzen)
	if v := strings.TrimSpace(r.PostFormValue("keep_days")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			n = -1 // SaveSettings lehnt es ab
		}
		s.KeepDays = n
	}
	s.NotifyUnexpected = r.PostFormValue("notify_unexpected") == "on" // das Formular traegt alle Schalter: nicht angehakt heisst aus
	s.NotifyNew = r.PostFormValue("notify_new") == "on"
	s.NotifyListen = r.PostFormValue("notify_listen") == "on"
	s.UPnP = r.PostFormValue("upnp") == "on"
	s.UPnPURL = strings.TrimSpace(r.PostFormValue("upnp_url"))
	for _, v := range r.PostForm["subnet"] {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			s.Subnets = append(s.Subnets, id)
		}
	}
	if err := m.SaveSettings(r.Context(), s); err != nil {
		m.back(w, r, "danger", m.errText(r, err))
		return
	}
	m.audit(r, "exposure.settings", "settings", "interval="+strconv.Itoa(s.IntervalHours)+"h subnets="+strconv.Itoa(len(s.Subnets)))
	m.back(w, r, "success", m.g.T(r, "common.saved"))
}

// pageScan startet einen Lauf im Hintergrund (ein Scan kann Minuten dauern); laeuft schon einer, kommt ein Hinweis.
func (m *Module) pageScan(w http.ResponseWriter, r *http.Request) {
	if err := m.StartRun(); err != nil {
		m.back(w, r, "warning", m.errText(r, err))
		return
	}
	m.audit(r, "exposure.scan", "", "")
	m.back(w, r, "success", m.g.T(r, "exposure.flash.started"))
}

func (m *Module) pageExpectedAdd(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("port")))
	if err != nil {
		port = 0 // AddExpected lehnt Port 0 ab
	}
	proto := r.PostFormValue("proto")
	if err := m.AddExpected(r.Context(), proto, port, r.PostFormValue("note")); err != nil {
		m.back(w, r, "danger", m.errText(r, err))
		return
	}
	m.audit(r, "exposure.expected_add", strings.ToLower(proto)+"/"+strconv.Itoa(port), "")
	m.back(w, r, "success", m.g.T(r, "common.saved"))
}

func (m *Module) pageExpectedDelete(w http.ResponseWriter, r *http.Request) {
	port, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue("port")))
	proto := r.PostFormValue("proto")
	if err := m.RemoveExpected(r.Context(), proto, port); err != nil {
		m.back(w, r, "danger", m.errText(r, err))
		return
	}
	m.audit(r, "exposure.expected_remove", strings.ToLower(proto)+"/"+strconv.Itoa(port), "")
	m.back(w, r, "success", m.g.T(r, "common.saved"))
}
