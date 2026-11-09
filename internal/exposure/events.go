package exposure

import (
	"context"
	"database/sql"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// Arten von Ereignissen im Verlauf.
const (
	EventForwardNew  = "forward_new"  // neue Weiterleitung des Routers (auch: wieder da)
	EventForwardGone = "forward_gone" // Weiterleitung weggefallen
	EventListenNew   = "listen_new"   // neuer lauschender Port auf der Node oder einem Geraet (nicht in der Baseline)
	EventListenGone  = "listen_gone"  // lauschender Port weggefallen
)

// Event ist ein Eintrag im Verlauf.
type Event struct {
	ID       int64
	At       time.Time
	Kind     string
	Proto    string
	Port     int
	Address  string // bei Weiterleitungen das Ziel im LAN, bei lauschenden Ports "self" oder das Geraet
	Detail   string // bei Weiterleitungen "Adresse:Port" des Ziels, bei lauschenden Ports der Dienst
	Notified bool   // fuer eine Meldung ausgewertet (gemeldet oder bewusst nicht gemeldet)
}

// txer sind die Zugriffe, die die Speicherfunktionen innerhalb einer Transaktion brauchen.
type txer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// addEvent schreibt ein Ereignis (in der Transaktion des Aufrufers).
func addEvent(ctx context.Context, tx execer, now time.Time, kind, proto string, port int, address, detail string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO exposure_events (at, kind, proto, port, address, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		store.FormatTime(now), kind, proto, port, address, detail)
	return err
}

// Events liefert den Verlauf, neueste zuerst. limit unter 1 gilt als 50, ueber 500 als 500.
func (m *Module) Events(ctx context.Context, limit int) ([]Event, error) {
	switch {
	case limit < 1:
		limit = 50
	case limit > 500:
		limit = 500
	}
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT id, at, kind, proto, port, address, detail, notified FROM exposure_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var at string
		var n int
		if err := rows.Scan(&e.ID, &at, &e.Kind, &e.Proto, &e.Port, &e.Address, &e.Detail, &n); err != nil {
			return nil, err
		}
		e.At, e.Notified = store.ParseTime(at), n != notifyPending
		out = append(out, e)
	}
	return out, rows.Err()
}

// CleanupEvents loescht Ereignisse, die aelter sind als keep_days (0 = unbegrenzt: nichts wird geloescht).
func (m *Module) CleanupEvents(ctx context.Context, now time.Time) (int, error) {
	days := m.LoadSettings(ctx).KeepDays
	if days <= 0 {
		return 0, nil
	}
	res, err := m.core.Writer().ExecContext(ctx, `DELETE FROM exposure_events WHERE at < ?`, store.FormatTime(now.Add(-time.Duration(days)*24*time.Hour)))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
