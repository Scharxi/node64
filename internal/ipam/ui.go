package ipam

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"strconv"
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

// statusFilters sind die Filter der Adressliste (leer = alle).
var statusFilters = []Status{StatusNew, StatusUsed, StatusOffline, StatusReserved}

// uiRoutes registriert die Seite und ihre Formulare.
func (m *Module) uiRoutes(mux *http.ServeMux, g module.Guards) {
	page := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /ipam", page(m.pageOverview))
	mux.Handle("POST /ipam/subnets", page(m.pageSubnetAdd))
	mux.Handle("POST /ipam/subnets/{id}/delete", page(m.pageSubnetDelete))
	mux.Handle("POST /ipam/subnets/{id}/ack-all", page(m.pageAckAll))
	mux.Handle("POST /ipam/addresses", page(m.pageAddressAdd))
	mux.Handle("POST /ipam/addresses/{id}", page(m.pageAddressSave))
	mux.Handle("POST /ipam/addresses/{id}/ack", page(m.pageAddressAck))
	mux.Handle("POST /ipam/addresses/{id}/ignore", page(m.pageAddressIgnore))
	mux.Handle("POST /ipam/addresses/{id}/delete", page(m.pageAddressDelete))
}

// cardView ist die Karte eines Subnetzes.
type cardView struct {
	Subnet   Subnet
	Stats    SubnetStats
	IPv6     bool
	BarWidth float64
	BarClass string
	Selected bool
}

// rowView ist eine Zeile der Adressliste.
type rowView struct {
	Address
	Display  string
	Status   Status
	Conflict bool
}

type overviewData struct {
	Cards    []cardView
	Selected *cardView
	Rows     []rowView
	Filter   Status
	Filters  []Status
	Sources  []SourceState
	Outside  int
}

func (m *Module) pageOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now().UTC()
	subs, err := m.Subnets(ctx)
	var stats map[int64]SubnetStats
	if err == nil {
		stats, err = m.Stats(ctx, now)
	}
	if err != nil {
		m.log.Error("ipam page", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	d := overviewData{Filters: statusFilters, Sources: m.SourceStatus(), Outside: m.Outside()}
	want, _ := strconv.ParseInt(r.URL.Query().Get("subnet"), 10, 64)
	for _, s := range subs {
		c := cardView{Subnet: s, Stats: stats[s.ID], IPv6: s.CIDR.Addr().Is6()}
		if c.Stats.Size > 0 {
			pct := float64(c.Stats.Used) * 100 / float64(c.Stats.Size)
			c.BarWidth, c.BarClass = module.BarWidth(pct, c.Stats.Used > 0), module.BarClassOf(pct, false)
		}
		d.Cards = append(d.Cards, c)
	}
	for i := range d.Cards {
		if d.Cards[i].Subnet.ID == want || (d.Selected == nil && i == 0 && want == 0) {
			d.Selected = &d.Cards[i]
		}
	}
	if d.Selected == nil && len(d.Cards) > 0 {
		d.Selected = &d.Cards[0]
	}
	if d.Selected != nil {
		d.Selected.Selected = true
		for _, f := range statusFilters {
			if string(f) == r.URL.Query().Get("status") {
				d.Filter = f
			}
		}
		list, err := m.Addresses(ctx, d.Selected.Subnet.ID)
		if err != nil {
			m.log.Error("ipam page", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		for _, a := range list {
			st := a.StatusAt(now)
			if d.Filter != "" && st != d.Filter {
				continue
			}
			d.Rows = append(d.Rows, rowView{Address: a, Display: a.DisplayName(), Status: st, Conflict: a.ConflictAt(now)})
		}
	}
	m.g.Render(w, r, http.StatusOK, Name+"/overview", "ipam.title", d)
}

// back leitet auf die Seite zurueck (mit dem gewaehlten Subnetz), optional mit Meldung.
func (m *Module) back(w http.ResponseWriter, r *http.Request, kind, text string, subnetID int64) {
	if text != "" {
		m.g.Flash(w, r, kind, text)
	}
	to := "/ipam"
	if subnetID != 0 {
		to += "?subnet=" + strconv.FormatInt(subnetID, 10)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// formSubnet liest das Subnetz aus dem Formular (verstecktes Feld "subnet").
func formSubnet(r *http.Request) int64 {
	n, _ := strconv.ParseInt(r.PostFormValue("subnet"), 10, 64)
	return n
}

func pathID(r *http.Request) int64 {
	n, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return n
}

// errText uebersetzt einen Fehler des Moduls in die Sprache des Aufrufers.
func (m *Module) errText(r *http.Request, err error) string {
	keys := []struct {
		err error
		key string
	}{
		{ErrInvalidCIDR, "ipam.err.cidr"}, {ErrOverlap, "ipam.err.overlap"}, {ErrInvalidLabel, "ipam.err.label"},
		{ErrInvalidMAC, "ipam.err.mac"}, {ErrInvalidIP, "ipam.err.ip"}, {ErrOutsideSubnet, "ipam.err.outside"},
		{ErrExists, "ipam.err.exists"}, {ErrNotFound, "ipam.err.notfound"},
	}
	for _, k := range keys {
		if errors.Is(err, k.err) {
			return m.g.T(r, k.key)
		}
	}
	m.log.Error("ipam", "err", err)
	return m.g.T(r, "common.error")
}

func (m *Module) audit(r *http.Request, action, target, details string) {
	if m.g.Audit != nil {
		m.g.Audit(r, action, target, details)
	}
}

func (m *Module) pageSubnetAdd(w http.ResponseWriter, r *http.Request) {
	s, err := m.AddSubnet(r.Context(), r.PostFormValue("name"), r.PostFormValue("cidr"), r.PostFormValue("note"))
	if err != nil {
		m.back(w, r, "danger", m.errText(r, err), 0)
		return
	}
	m.audit(r, "ipam.subnet_add", s.CIDR.String(), s.Name)
	m.back(w, r, "success", m.g.T(r, "ipam.flash.subnet_added"), s.ID)
}

func (m *Module) pageSubnetDelete(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if err := m.DeleteSubnet(r.Context(), id); err != nil {
		m.back(w, r, "danger", m.errText(r, err), 0)
		return
	}
	m.audit(r, "ipam.subnet_delete", strconv.FormatInt(id, 10), "")
	m.back(w, r, "success", m.g.T(r, "ipam.flash.subnet_deleted"), 0)
}

func (m *Module) pageAckAll(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	n, err := m.AcknowledgeAll(r.Context(), id)
	if err != nil {
		m.back(w, r, "danger", m.errText(r, err), id)
		return
	}
	m.audit(r, "ipam.ack_all", strconv.FormatInt(id, 10), strconv.Itoa(n))
	m.back(w, r, "success", m.g.T(r, "ipam.flash.acked_all", "n", n), id)
}

// edit liest die Felder einer Adresse aus dem Formular.
func edit(r *http.Request) AddressEdit {
	return AddressEdit{Name: r.PostFormValue("name"), Note: r.PostFormValue("note"),
		Reserved: r.PostFormValue("reserved") == "on", ReservedMAC: r.PostFormValue("reserved_mac")}
}

func (m *Module) pageAddressAdd(w http.ResponseWriter, r *http.Request) {
	sid := formSubnet(r)
	a, err := m.AddAddress(r.Context(), sid, r.PostFormValue("ip"), edit(r))
	if err != nil {
		m.back(w, r, "danger", m.errText(r, err), sid)
		return
	}
	m.audit(r, "ipam.address_add", a.IP.String(), a.Name)
	m.back(w, r, "success", m.g.T(r, "ipam.flash.address_added"), sid)
}

func (m *Module) pageAddressSave(w http.ResponseWriter, r *http.Request) {
	sid := formSubnet(r)
	a, err := m.UpdateAddress(r.Context(), pathID(r), edit(r))
	if err != nil {
		m.back(w, r, "danger", m.errText(r, err), sid)
		return
	}
	m.audit(r, "ipam.address_save", a.IP.String(), a.Name)
	m.back(w, r, "success", m.g.T(r, "ipam.flash.address_saved"), sid)
}

func (m *Module) pageAddressAck(w http.ResponseWriter, r *http.Request) {
	sid := formSubnet(r)
	if err := m.Acknowledge(r.Context(), pathID(r)); err != nil {
		m.back(w, r, "danger", m.errText(r, err), sid)
		return
	}
	m.audit(r, "ipam.address_ack", strconv.FormatInt(pathID(r), 10), "")
	m.back(w, r, "", "", sid)
}

func (m *Module) pageAddressIgnore(w http.ResponseWriter, r *http.Request) {
	sid := formSubnet(r)
	on := r.PostFormValue("on") == "1"
	if err := m.SetIgnored(r.Context(), pathID(r), on); err != nil {
		m.back(w, r, "danger", m.errText(r, err), sid)
		return
	}
	m.audit(r, "ipam.address_ignore", strconv.FormatInt(pathID(r), 10), strconv.FormatBool(on))
	m.back(w, r, "", "", sid)
}

func (m *Module) pageAddressDelete(w http.ResponseWriter, r *http.Request) {
	sid := formSubnet(r)
	if err := m.DeleteAddress(r.Context(), pathID(r)); err != nil {
		m.back(w, r, "danger", m.errText(r, err), sid)
		return
	}
	m.audit(r, "ipam.address_delete", strconv.FormatInt(pathID(r), 10), "")
	m.back(w, r, "success", m.g.T(r, "ipam.flash.address_deleted"), sid)
}
