package exposure

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ipv64net/node64/internal/store"
)

// EvidenceUPnP: die Aussage stammt vom Router (aktive Weiterleitung per UPnP).
const EvidenceUPnP = "upnp"

var (
	ErrInvalidExpected = errors.New("exposure: invalid expected port")
	ErrNotFound        = errors.New("exposure: not found")
)

// External ist eine Weiterleitung, die ein Router meldet: externer Port auf ein Ziel im LAN.
type External struct {
	Proto        string // tcp oder udp
	Port         int    // externer Port
	Evidence     string
	InternalAddr string
	InternalPort int
	Description  string
	State        string // open | gone
	FirstSeen    time.Time
	LastSeen     time.Time
}

// Expected ist ein vom Nutzer erwarteter externer Port.
type Expected struct {
	Proto string
	Port  int
	Note  string
}

const externalCols = `proto, port, evidence, internal_addr, internal_port, description, state, first_seen, last_seen`

// recordExternal nimmt die Weiterleitungen einer Abfrage auf: offene Zeilen werden angelegt bzw. aktualisiert
// (first_seen bleibt), Zeilen derselben Evidenz, die in rows fehlen, werden "gone". Nur nach einer erfolgreichen
// Abfrage aufrufen: eine leere Liste ist dann gueltig und beendet alle bekannten Weiterleitungen.
func (m *Module) recordExternal(ctx context.Context, now time.Time, evidence string, rows []External) error {
	return m.recordExternalMode(ctx, now, evidence, rows, true)
}

// recordExternalMode wie recordExternal; markGone = false nimmt nur auf und setzt nichts auf "gone" (abgeschnittene
// Liste: sie sagt nichts ueber Eintraege jenseits der Grenze).
func (m *Module) recordExternalMode(ctx context.Context, now time.Time, evidence string, rows []External, markGone bool) error {
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ts := store.FormatTime(now)
	seen := map[string]bool{}
	for _, r := range rows {
		proto := strings.ToLower(r.Proto)
		var prev string
		perr := tx.QueryRowContext(ctx, `SELECT state FROM exposure_external WHERE proto = ? AND port = ? AND evidence = ?`, proto, r.Port, evidence).Scan(&prev)
		if perr != nil && perr != sql.ErrNoRows {
			return perr
		}
		if perr == sql.ErrNoRows || prev == "gone" {
			if err := addEvent(ctx, tx, now, EventForwardNew, proto, r.Port, r.InternalAddr, r.InternalAddr+":"+strconv.Itoa(r.InternalPort)); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO exposure_external (`+externalCols+`) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)
			ON CONFLICT(proto, port, evidence) DO UPDATE SET state = 'open', internal_addr = excluded.internal_addr,
			internal_port = excluded.internal_port, description = excluded.description, last_seen = excluded.last_seen`,
			proto, r.Port, evidence, r.InternalAddr, r.InternalPort, r.Description, ts, ts); err != nil {
			return err
		}
		seen[portKey(proto, r.Port)] = true
	}
	if !markGone {
		return tx.Commit()
	}
	open, err := tx.QueryContext(ctx, `SELECT proto, port, internal_addr, internal_port FROM exposure_external WHERE evidence = ? AND state = 'open'`, evidence)
	if err != nil {
		return err
	}
	var gone []External
	for open.Next() {
		var e External
		if err := open.Scan(&e.Proto, &e.Port, &e.InternalAddr, &e.InternalPort); err != nil {
			open.Close()
			return err
		}
		if !seen[portKey(e.Proto, e.Port)] {
			gone = append(gone, e)
		}
	}
	open.Close()
	for _, e := range gone {
		if _, err := tx.ExecContext(ctx, `UPDATE exposure_external SET state = 'gone' WHERE proto = ? AND port = ? AND evidence = ?`, e.Proto, e.Port, evidence); err != nil {
			return err
		}
		if err := addEvent(ctx, tx, now, EventForwardGone, e.Proto, e.Port, e.InternalAddr, e.InternalAddr+":"+strconv.Itoa(e.InternalPort)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Externals liefert alle bekannten Weiterleitungen (auch "gone"), nach Protokoll und Port.
func (m *Module) Externals(ctx context.Context) ([]External, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT `+externalCols+` FROM exposure_external ORDER BY proto, port, evidence`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []External
	for rows.Next() {
		var e External
		var first, last string
		if err := rows.Scan(&e.Proto, &e.Port, &e.Evidence, &e.InternalAddr, &e.InternalPort, &e.Description, &e.State, &first, &last); err != nil {
			return nil, err
		}
		e.FirstSeen, e.LastSeen = store.ParseTime(first), store.ParseTime(last)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Expecteds liefert die erwarteten Ports, nach Protokoll und Port.
func (m *Module) Expecteds(ctx context.Context) ([]Expected, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT proto, port, note FROM exposure_expected ORDER BY proto, port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Expected
	for rows.Next() {
		var e Expected
		if err := rows.Scan(&e.Proto, &e.Port, &e.Note); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// cleanNote trimmt eine Notiz und lehnt Steuerzeichen und mehr als 253 Zeichen ab.
func cleanNote(s string) (string, error) {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > 253 {
		return "", ErrInvalidExpected
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", ErrInvalidExpected
		}
	}
	return s, nil
}

// checkExpected prueft einen erwarteten Port und liefert Protokoll und Notiz in Normalform.
func checkExpected(proto string, port int, note string) (string, string, error) {
	proto = strings.ToLower(strings.TrimSpace(proto))
	if (proto != "tcp" && proto != "udp") || port < 1 || port > 65535 {
		return "", "", ErrInvalidExpected
	}
	note, err := cleanNote(note)
	return proto, note, err
}

// AddExpected traegt einen erwarteten Port ein (ein vorhandener wird aktualisiert).
func (m *Module) AddExpected(ctx context.Context, proto string, port int, note string) error {
	proto, note, err := checkExpected(proto, port, note)
	if err != nil {
		return err
	}
	_, err = m.core.Writer().ExecContext(ctx, `INSERT INTO exposure_expected (proto, port, note, created_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(proto, port) DO UPDATE SET note = excluded.note`, proto, port, note, store.Now())
	return err
}

// RemoveExpected loescht einen erwarteten Port; ErrNotFound, wenn es ihn nicht gibt.
func (m *Module) RemoveExpected(ctx context.Context, proto string, port int) error {
	res, err := m.core.Writer().ExecContext(ctx, `DELETE FROM exposure_expected WHERE proto = ? AND port = ?`, strings.ToLower(proto), port)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
