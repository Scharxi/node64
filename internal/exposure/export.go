package exposure

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/ipv64net/node64/internal/store"
)

// maxImportExpected begrenzt die erwarteten Ports einer Importdatei.
const maxImportExpected = 1000

type exportSettings struct {
	IntervalHours    int    `json:"interval_hours"`
	Ports            []int  `json:"ports"`
	UPnP             bool   `json:"upnp"`
	UPnPURL          string `json:"upnp_url"`
	KeepDays         int    `json:"keep_days"`
	NotifyUnexpected bool   `json:"notify_unexpected"`
	NotifyNew        bool   `json:"notify_new"`
	NotifyListen     bool   `json:"notify_listen"`
}

type exportExpected struct {
	Proto string `json:"proto"`
	Port  int    `json:"port"`
	Note  string `json:"note"`
}

type exportData struct {
	Settings exportSettings   `json:"settings"`
	Expected []exportExpected `json:"expected"`
}

// Export liefert die Konfiguration. Die Auswahl der Subnetze gehoert nicht dazu (sie haengt an den IPAM-Daten dieser Node).
func (m *Module) Export(ctx context.Context) (any, error) {
	s := m.LoadSettings(ctx)
	out := exportData{Settings: exportSettings{IntervalHours: s.IntervalHours, Ports: s.Ports, UPnP: s.UPnP, UPnPURL: s.UPnPURL, KeepDays: s.KeepDays,
		NotifyUnexpected: s.NotifyUnexpected, NotifyNew: s.NotifyNew, NotifyListen: s.NotifyListen}, Expected: []exportExpected{}}
	if out.Settings.Ports == nil {
		out.Settings.Ports = []int{}
	}
	list, err := m.Expecteds(ctx)
	if err != nil {
		return nil, err
	}
	for _, e := range list {
		out.Expected = append(out.Expected, exportExpected{Proto: e.Proto, Port: e.Port, Note: e.Note})
	}
	return out, nil
}

// importSettings: fehlende Felder lassen den Wert, wie er ist.
type importSettings struct {
	IntervalHours    *int    `json:"interval_hours"`
	Ports            *[]int  `json:"ports"`
	UPnP             *bool   `json:"upnp"`
	UPnPURL          *string `json:"upnp_url"`
	KeepDays         *int    `json:"keep_days"`
	NotifyUnexpected *bool   `json:"notify_unexpected"`
	NotifyNew        *bool   `json:"notify_new"`
	NotifyListen     *bool   `json:"notify_listen"`
}

type importData struct {
	Settings *importSettings   `json:"settings"`
	Expected *[]exportExpected `json:"expected"`
}

// merge legt die gegebenen Felder ueber s.
func (in importSettings) merge(s Settings) Settings {
	if in.IntervalHours != nil {
		s.IntervalHours = *in.IntervalHours
	}
	if in.Ports != nil {
		s.Ports = slices.Clone(*in.Ports)
	}
	if in.UPnP != nil {
		s.UPnP = *in.UPnP
	}
	if in.UPnPURL != nil {
		s.UPnPURL = *in.UPnPURL
	}
	if in.KeepDays != nil {
		s.KeepDays = *in.KeepDays
	}
	if in.NotifyUnexpected != nil {
		s.NotifyUnexpected = *in.NotifyUnexpected
	}
	if in.NotifyNew != nil {
		s.NotifyNew = *in.NotifyNew
	}
	if in.NotifyListen != nil {
		s.NotifyListen = *in.NotifyListen
	}
	return s
}

// checkImported prueft Einstellungen wie SaveSettings, ohne die Subnetze (die bleiben unveraendert).
func checkImported(s Settings) error {
	if !slices.Contains(IntervalOptions, s.IntervalHours) {
		return ErrInvalidInterval
	}
	if _, err := ScanPorts(s.Ports); err != nil {
		return err
	}
	if !slices.Contains(KeepDaysOptions, s.KeepDays) {
		return ErrInvalidKeepDays
	}
	if s.UPnPURL != "" {
		if _, err := SafeLocation(s.UPnPURL); err != nil {
			return err
		}
	}
	return nil
}

// Import uebernimmt Einstellungen und erwartete Ports. Es wird zuerst alles geprueft und erst danach geschrieben: ein
// Fehler aendert nichts. Erwartete Ports kommen zu den vorhandenen hinzu (ein vorhandener bekommt die neue Notiz). Die
// Subnetz-Auswahl bleibt unberuehrt. Rueckgabe: Zahl der uebernommenen Eintraege (Einstellungen zaehlen als einer).
func (m *Module) Import(ctx context.Context, raw json.RawMessage) (int, error) {
	var in importData
	if err := json.Unmarshal(raw, &in); err != nil {
		return 0, fmt.Errorf("exposure: %w", err)
	}
	var settings *Settings
	if in.Settings != nil {
		s := in.Settings.merge(m.LoadSettings(ctx))
		if err := checkImported(s); err != nil {
			return 0, err
		}
		settings = &s
	}
	var expected []exportExpected
	if in.Expected != nil {
		if len(*in.Expected) > maxImportExpected {
			return 0, ErrInvalidExpected
		}
		for _, e := range *in.Expected {
			proto, note, err := checkExpected(e.Proto, e.Port, e.Note)
			if err != nil {
				return 0, err
			}
			expected = append(expected, exportExpected{Proto: proto, Port: e.Port, Note: note})
		}
	}
	n := 0
	if err := m.writeExpected(ctx, expected); err != nil {
		return 0, err
	}
	n += len(expected)
	if settings != nil {
		if err := m.saveRaw(ctx, *settings); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// writeExpected schreibt die geprueften erwarteten Ports in einer Transaktion.
func (m *Module) writeExpected(ctx context.Context, list []exportExpected) error {
	if len(list) == 0 {
		return nil
	}
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, e := range list {
		if _, err := tx.ExecContext(ctx, `INSERT INTO exposure_expected (proto, port, note, created_at) VALUES (?, ?, ?, ?)
			ON CONFLICT(proto, port) DO UPDATE SET note = excluded.note`, e.Proto, e.Port, e.Note, store.Now()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
