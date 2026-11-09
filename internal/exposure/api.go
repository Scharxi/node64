package exposure

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/module"
)

// Lokale JSON-API des Moduls (Doku: internal/web/static/openapi.json, Tag "Exposure").

const maxBody = 64 << 10

func (m *Module) apiRoutes(mux *http.ServeMux, g module.Guards) {
	api := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /api/exposure/status", api(m.apiStatus))
	mux.Handle("GET /api/exposure/listen", api(m.apiListen))
	mux.Handle("GET /api/exposure/settings", api(m.apiSettingsGet))
	mux.Handle("PUT /api/exposure/settings", api(m.apiSettingsPut))
	mux.Handle("POST /api/exposure/scan", api(m.apiScan))
	mux.Handle("GET /api/exposure/overview", api(m.apiOverview))
	mux.Handle("GET /api/exposure/expected", api(m.apiExpectedList))
	mux.Handle("POST /api/exposure/expected", api(m.apiExpectedAdd))
	mux.Handle("DELETE /api/exposure/expected/{proto}/{port}", api(m.apiExpectedDelete))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func ts(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// apiErr bildet einen Fehler des Moduls auf Status und Meldung ab; Unbekanntes geht als 500 ohne Einzelheiten raus.
func (m *Module) apiErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrBusy):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	case errors.Is(err, ErrInvalidPorts), errors.Is(err, ErrTooManyPorts), errors.Is(err, ErrInvalidInterval), errors.Is(err, ErrUnknownSubnet),
		errors.Is(err, ErrSubnetNotPrivate), errors.Is(err, ErrInvalidExpected), errors.Is(err, ErrUnsafeURL):
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
	default:
		m.log.Error("exposure api", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

func (m *Module) apiStatus(w http.ResponseWriter, r *http.Request) {
	st := m.Status()
	writeJSON(w, http.StatusOK, map[string]any{"self_known": st.SelfKnown, "last_self_at": ts(st.LastSelfAt), "last_scan_at": ts(st.LastScanAt),
		"running": st.Running, "hosts": st.Hosts, "error": st.LastErr,
		"upnp_at": ts(st.UPnPAt), "upnp_error": st.UPnPErr, "external_ip": st.ExternalIP, "mappings": st.Mappings})
}

type listenJSON struct {
	Address   string     `json:"address"`
	Proto     string     `json:"proto"`
	Port      int        `json:"port"`
	State     string     `json:"state"`
	Service   string     `json:"service"`
	Bind      string     `json:"bind"`
	Owner     string     `json:"owner"`
	FirstSeen *time.Time `json:"first_seen"`
	LastSeen  *time.Time `json:"last_seen"`
	Source    string     `json:"source"`
}

func (m *Module) apiListen(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	if address != "" && address != SelfAddress {
		a, err := netip.ParseAddr(address)
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, "address must be \"self\" or an ip address")
			return
		}
		address = a.Unmap().WithZone("").String()
	}
	rows, err := m.Listening(r.Context(), address)
	if err != nil {
		m.apiErr(w, err)
		return
	}
	out := make([]listenJSON, 0, len(rows))
	for _, l := range rows {
		out = append(out, listenJSON{Address: l.Address, Proto: l.Proto, Port: l.Port, State: l.State, Service: l.Service, Bind: l.Bind,
			Owner: l.Owner, FirstSeen: ts(l.FirstSeen), LastSeen: ts(l.LastSeen), Source: l.Source})
	}
	writeJSON(w, http.StatusOK, out)
}

type settingsJSON struct {
	IntervalHours int     `json:"interval_hours"`
	Ports         []int   `json:"ports"`
	Subnets       []int64 `json:"subnets"`
	UPnP          bool    `json:"upnp"`
	UPnPURL       string  `json:"upnp_url"`
}

func settingsOut(s Settings) settingsJSON {
	out := settingsJSON{IntervalHours: s.IntervalHours, Ports: s.Ports, Subnets: s.Subnets, UPnP: s.UPnP, UPnPURL: s.UPnPURL}
	if out.Ports == nil {
		out.Ports = []int{}
	}
	if out.Subnets == nil {
		out.Subnets = []int64{}
	}
	return out
}

func (m *Module) apiSettingsGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, settingsOut(m.LoadSettings(r.Context())))
}

// apiSettingsPut ersetzt alle Einstellungen (fehlende Felder gelten als leer).
func (m *Module) apiSettingsPut(w http.ResponseWriter, r *http.Request) {
	var in settingsJSON
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	s := Settings{IntervalHours: in.IntervalHours, Ports: in.Ports, Subnets: in.Subnets, UPnP: in.UPnP, UPnPURL: in.UPnPURL}
	if err := m.SaveSettings(r.Context(), s); err != nil {
		m.apiErr(w, err)
		return
	}
	m.audit(r, "exposure.settings", "settings", "api")
	writeJSON(w, http.StatusOK, settingsOut(m.LoadSettings(r.Context())))
}

// apiScan startet einen Lauf im Hintergrund; laeuft schon einer, kommt 409.
func (m *Module) apiScan(w http.ResponseWriter, r *http.Request) {
	if err := m.StartRun(); err != nil {
		m.apiErr(w, err)
		return
	}
	m.audit(r, "exposure.scan", "", "api")
	writeJSON(w, http.StatusAccepted, map[string]bool{"started": true})
}

type reachJSON struct {
	Proto        string     `json:"proto"`
	Port         int        `json:"port"`
	Level        Level      `json:"level"`
	Class        Class      `json:"class"`
	Device       string     `json:"device"`
	InternalAddr string     `json:"internal_addr"`
	InternalPort int        `json:"internal_port"`
	Service      string     `json:"service"`
	Description  string     `json:"description"`
	Listening    bool       `json:"listening"`
	New          bool       `json:"new"`
	FirstSeen    *time.Time `json:"first_seen"`
	LastSeen     *time.Time `json:"last_seen"`
}

type goneJSON struct {
	Proto        string     `json:"proto"`
	Port         int        `json:"port"`
	InternalAddr string     `json:"internal_addr"`
	InternalPort int        `json:"internal_port"`
	Description  string     `json:"description"`
	FirstSeen    *time.Time `json:"first_seen"`
	LastSeen     *time.Time `json:"last_seen"`
}

// apiOverview ist die Gesamtsicht: Weiterleitungen des Routers mit Stufe und Einordnung, dazu die kuerzlich weggefallenen.
func (m *Module) apiOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := m.Listening(ctx, "")
	if err != nil {
		m.apiErr(w, err)
		return
	}
	var subs []SubnetRef
	if m.subnets != nil {
		subs, _ = m.subnets(ctx)
	}
	open, gone, _ := m.reachOverview(ctx, rows, subs)
	st, set := m.Status(), m.LoadSettings(ctx)
	out := struct {
		UPnP map[string]any `json:"upnp"`
		Open []reachJSON    `json:"open"`
		Gone []goneJSON     `json:"gone"`
	}{UPnP: map[string]any{"enabled": set.UPnP, "last_at": ts(st.UPnPAt), "error": st.UPnPErr, "external_ip": st.ExternalIP,
		"mappings": st.Mappings, "truncated": st.UPnPTruncated, "location": st.UPnPLocation, "gateways": st.UPnPGateways}, Open: []reachJSON{}, Gone: []goneJSON{}}
	for _, o := range open {
		out.Open = append(out.Open, reachJSON{Proto: o.Proto, Port: o.Port, Level: o.Level, Class: o.Class, Device: o.Device, InternalAddr: o.InternalAddr,
			InternalPort: o.InternalPort, Service: o.Service, Description: o.Description, Listening: o.Listening, New: o.New, FirstSeen: ts(o.FirstSeen), LastSeen: ts(o.LastSeen)})
	}
	for _, g := range gone {
		out.Gone = append(out.Gone, goneJSON{Proto: g.Proto, Port: g.Port, InternalAddr: g.InternalAddr, InternalPort: g.InternalPort, Description: g.Description,
			FirstSeen: ts(g.FirstSeen), LastSeen: ts(g.LastSeen)})
	}
	writeJSON(w, http.StatusOK, out)
}

type expectedJSON struct {
	Proto string `json:"proto"`
	Port  int    `json:"port"`
	Note  string `json:"note"`
}

func (m *Module) apiExpectedList(w http.ResponseWriter, r *http.Request) {
	list, err := m.Expecteds(r.Context())
	if err != nil {
		m.apiErr(w, err)
		return
	}
	out := make([]expectedJSON, 0, len(list))
	for _, e := range list {
		out = append(out, expectedJSON{Proto: e.Proto, Port: e.Port, Note: e.Note})
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) apiExpectedAdd(w http.ResponseWriter, r *http.Request) {
	var in expectedJSON
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if err := m.AddExpected(r.Context(), in.Proto, in.Port, in.Note); err != nil {
		m.apiErr(w, err)
		return
	}
	in.Proto = strings.ToLower(strings.TrimSpace(in.Proto))
	m.audit(r, "exposure.expected_add", in.Proto+"/"+strconv.Itoa(in.Port), "api")
	writeJSON(w, http.StatusCreated, in)
}

func (m *Module) apiExpectedDelete(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "port must be a number")
		return
	}
	proto := r.PathValue("proto")
	if err := m.RemoveExpected(r.Context(), proto, port); err != nil {
		m.apiErr(w, err)
		return
	}
	m.audit(r, "exposure.expected_remove", strings.ToLower(proto)+"/"+strconv.Itoa(port), "api")
	w.WriteHeader(http.StatusNoContent)
}
