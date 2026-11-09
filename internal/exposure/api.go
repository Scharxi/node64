package exposure

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
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
	case errors.Is(err, ErrInvalidPorts), errors.Is(err, ErrTooManyPorts), errors.Is(err, ErrInvalidInterval), errors.Is(err, ErrUnknownSubnet), errors.Is(err, ErrSubnetNotPrivate):
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
	default:
		m.log.Error("exposure api", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

func (m *Module) apiStatus(w http.ResponseWriter, r *http.Request) {
	st := m.Status()
	writeJSON(w, http.StatusOK, map[string]any{"self_known": st.SelfKnown, "last_self_at": ts(st.LastSelfAt), "last_scan_at": ts(st.LastScanAt),
		"running": st.Running, "hosts": st.Hosts, "error": st.LastErr})
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
}

func settingsOut(s Settings) settingsJSON {
	out := settingsJSON{IntervalHours: s.IntervalHours, Ports: s.Ports, Subnets: s.Subnets}
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
	s := Settings{IntervalHours: in.IntervalHours, Ports: in.Ports, Subnets: in.Subnets}
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
