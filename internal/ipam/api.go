package ipam

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/module"
)

// Lokale JSON-API des Moduls (Doku: internal/web/static/openapi.json, Tag "IPAM").

const maxBody = 64 << 10

func (m *Module) apiRoutes(mux *http.ServeMux, g module.Guards) {
	api := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /api/ipam/status", api(m.apiStatus))
	mux.Handle("GET /api/ipam/subnets", api(m.apiSubnets))
	mux.Handle("POST /api/ipam/subnets", api(m.apiSubnetCreate))
	mux.Handle("DELETE /api/ipam/subnets/{id}", api(m.apiSubnetDelete))
	mux.Handle("GET /api/ipam/subnets/{id}/addresses", api(m.apiAddresses))
	mux.Handle("POST /api/ipam/subnets/{id}/addresses", api(m.apiAddressCreate))
	mux.Handle("POST /api/ipam/subnets/{id}/ack-all", api(m.apiAckAll))
	mux.Handle("PUT /api/ipam/addresses/{id}", api(m.apiAddressUpdate))
	mux.Handle("POST /api/ipam/addresses/{id}/ack", api(m.apiAddressAck))
	mux.Handle("DELETE /api/ipam/addresses/{id}", api(m.apiAddressDelete))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// apiErr bildet einen Fehler des Moduls auf Status und Meldung ab; unbekannte Fehler gehen als 500 ohne Einzelheiten raus.
func (m *Module) apiErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	case errors.Is(err, ErrOverlap), errors.Is(err, ErrExists):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrInvalidCIDR), errors.Is(err, ErrInvalidLabel), errors.Is(err, ErrInvalidMAC),
		errors.Is(err, ErrInvalidIP), errors.Is(err, ErrOutsideSubnet):
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
	default:
		m.log.Error("ipam api", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

// decode liest den JSON-Rumpf (hoechstens 64 KB); false = Antwort 400 ist schon gesendet.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return false
	}
	return true
}

func ts(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

type subnetJSON struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CIDR      string    `json:"cidr"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
	Size      uint64    `json:"size"`
	Used      int       `json:"used"`
	Reserved  int       `json:"reserved"`
	New       int       `json:"new"`
	Conflicts int       `json:"conflicts"`
}

type addressJSON struct {
	ID           int64      `json:"id"`
	IP           string     `json:"ip"`
	Name         string     `json:"name"`
	SourceName   string     `json:"source_name"`
	MAC          string     `json:"mac"`
	ReservedMAC  string     `json:"reserved_mac"`
	Note         string     `json:"note"`
	Reserved     bool       `json:"reserved"`
	Acknowledged bool       `json:"acknowledged"`
	Ignored      bool       `json:"ignored"`
	Status       Status     `json:"status"`
	Conflict     bool       `json:"conflict"`
	FirstSeen    *time.Time `json:"first_seen"`
	LastSeen     *time.Time `json:"last_seen"`
	LastSource   string     `json:"last_source"`
}

func addressOut(a Address, now time.Time) addressJSON {
	return addressJSON{ID: a.ID, IP: a.IP.String(), Name: a.Name, SourceName: a.SourceName, MAC: a.MAC, ReservedMAC: a.ReservedMAC,
		Note: a.Note, Reserved: a.Reserved, Acknowledged: a.Acknowledged, Ignored: a.Ignored, Status: a.StatusAt(now),
		Conflict: a.ConflictAt(now), FirstSeen: ts(a.FirstSeen), LastSeen: ts(a.LastSeen), LastSource: a.LastSource}
}

func (m *Module) subnetsOut(ctx context.Context) ([]subnetJSON, error) {
	subs, err := m.Subnets(ctx)
	if err != nil {
		return nil, err
	}
	stats, err := m.Stats(ctx, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	out := make([]subnetJSON, 0, len(subs))
	for _, s := range subs {
		st := stats[s.ID]
		out = append(out, subnetJSON{ID: s.ID, Name: s.Name, CIDR: s.CIDR.String(), Note: s.Note, CreatedAt: s.CreatedAt.UTC(),
			Size: st.Size, Used: st.Used, Reserved: st.Reserved, New: st.New, Conflicts: st.Conflicts})
	}
	return out, nil
}

func (m *Module) apiStatus(w http.ResponseWriter, r *http.Request) {
	subs, err := m.subnetsOut(r.Context())
	if err != nil {
		m.apiErr(w, err)
		return
	}
	out := map[string]any{"subnets": len(subs), "outside": m.Outside()}
	var used, newN, conflicts int
	for _, s := range subs {
		used, newN, conflicts = used+s.Used, newN+s.New, conflicts+s.Conflicts
	}
	out["used"], out["new"], out["conflicts"] = used, newN, conflicts
	type srcJSON struct {
		Name   string     `json:"name"`
		LastOK *time.Time `json:"last_ok"`
		Error  string     `json:"error"`
		Count  int        `json:"count"`
	}
	sources := []srcJSON{}
	for _, s := range m.SourceStatus() {
		sources = append(sources, srcJSON{Name: s.Name, LastOK: ts(s.LastOK), Error: s.Err, Count: s.Count})
	}
	out["sources"] = sources
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) apiSubnets(w http.ResponseWriter, r *http.Request) {
	out, err := m.subnetsOut(r.Context())
	if err != nil {
		m.apiErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) apiSubnetCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
		CIDR string `json:"cidr"`
		Note string `json:"note"`
	}
	if !decode(w, r, &in) {
		return
	}
	s, err := m.AddSubnet(r.Context(), in.Name, in.CIDR, in.Note)
	if err != nil {
		m.apiErr(w, err)
		return
	}
	m.audit(r, "ipam.subnet_add", s.CIDR.String(), s.Name)
	writeJSON(w, http.StatusCreated, subnetJSON{ID: s.ID, Name: s.Name, CIDR: s.CIDR.String(), Note: s.Note, CreatedAt: s.CreatedAt.UTC(), Size: HostCount(s.CIDR)})
}

func (m *Module) apiSubnetDelete(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if err := m.DeleteSubnet(r.Context(), id); err != nil {
		m.apiErr(w, err)
		return
	}
	m.audit(r, "ipam.subnet_delete", strconv.FormatInt(id, 10), "")
	w.WriteHeader(http.StatusNoContent)
}

// subnetExists antwortet mit 404, wenn es das Netz nicht gibt.
func (m *Module) subnetExists(w http.ResponseWriter, r *http.Request, id int64) bool {
	subs, err := m.Subnets(r.Context())
	if err != nil {
		m.apiErr(w, err)
		return false
	}
	for _, s := range subs {
		if s.ID == id {
			return true
		}
	}
	m.apiErr(w, ErrNotFound)
	return false
}

func (m *Module) apiAddresses(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if !m.subnetExists(w, r, id) {
		return
	}
	var filter Status
	if q := r.URL.Query().Get("status"); q != "" {
		for _, f := range statusFilters {
			if string(f) == q {
				filter = f
			}
		}
		if filter == "" {
			writeErr(w, http.StatusUnprocessableEntity, "status must be new, used, offline or reserved")
			return
		}
	}
	list, err := m.Addresses(r.Context(), id)
	if err != nil {
		m.apiErr(w, err)
		return
	}
	now := time.Now().UTC()
	out := make([]addressJSON, 0, len(list))
	for _, a := range list {
		if filter == "" || a.StatusAt(now) == filter {
			out = append(out, addressOut(a, now))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

type addressIn struct {
	IP          string `json:"ip"`
	Name        string `json:"name"`
	Note        string `json:"note"`
	Reserved    bool   `json:"reserved"`
	ReservedMAC string `json:"reserved_mac"`
}

func (a addressIn) edit() AddressEdit {
	return AddressEdit{Name: a.Name, Note: a.Note, Reserved: a.Reserved, ReservedMAC: a.ReservedMAC}
}

func (m *Module) apiAddressCreate(w http.ResponseWriter, r *http.Request) {
	var in addressIn
	if !decode(w, r, &in) {
		return
	}
	a, err := m.AddAddress(r.Context(), pathID(r), in.IP, in.edit())
	if err != nil {
		m.apiErr(w, err)
		return
	}
	m.audit(r, "ipam.address_add", a.IP.String(), a.Name)
	writeJSON(w, http.StatusCreated, addressOut(a, time.Now().UTC()))
}

// apiAddressUpdate ersetzt Name, Notiz und Reservierung (fehlende Felder loeschen sie).
func (m *Module) apiAddressUpdate(w http.ResponseWriter, r *http.Request) {
	var in addressIn
	if !decode(w, r, &in) {
		return
	}
	a, err := m.UpdateAddress(r.Context(), pathID(r), in.edit())
	if err != nil {
		m.apiErr(w, err)
		return
	}
	m.audit(r, "ipam.address_save", a.IP.String(), a.Name)
	writeJSON(w, http.StatusOK, addressOut(a, time.Now().UTC()))
}

func (m *Module) apiAddressAck(w http.ResponseWriter, r *http.Request) {
	if err := m.Acknowledge(r.Context(), pathID(r)); err != nil {
		m.apiErr(w, err)
		return
	}
	m.audit(r, "ipam.address_ack", strconv.FormatInt(pathID(r), 10), "")
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) apiAckAll(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if !m.subnetExists(w, r, id) {
		return
	}
	n, err := m.AcknowledgeAll(r.Context(), id)
	if err != nil {
		m.apiErr(w, err)
		return
	}
	m.audit(r, "ipam.ack_all", strconv.FormatInt(id, 10), strconv.Itoa(n))
	writeJSON(w, http.StatusOK, map[string]int{"acknowledged": n})
}

func (m *Module) apiAddressDelete(w http.ResponseWriter, r *http.Request) {
	if err := m.DeleteAddress(r.Context(), pathID(r)); err != nil {
		m.apiErr(w, err)
		return
	}
	m.audit(r, "ipam.address_delete", strconv.FormatInt(pathID(r), 10), "")
	w.WriteHeader(http.StatusNoContent)
}
