package exposure

import (
	"context"
	"database/sql"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func itoa(n int) string { return strconv.Itoa(n) }

const listenCols = `address, proto, port, state, service, bind, owner, first_seen, last_seen, source`

// upsert nimmt einen offenen Port auf: first_seen bleibt, last_seen rueckt vor, ein "gone" wird wieder "open". Neu angelegt
// oder wieder geoeffnet ergibt ein Ereignis listen_new, ausser in der Baseline der Adresse (baseline = die Adresse hatte
// vor diesem Aufruf noch keine Zeile).
func upsert(ctx context.Context, tx txer, now time.Time, r Listen, baseline bool) error {
	var prev string
	err := tx.QueryRowContext(ctx, `SELECT state FROM exposure_listen WHERE address = ? AND proto = ? AND port = ?`, r.Address, r.Proto, r.Port).Scan(&prev)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	ts := store.FormatTime(now)
	if _, err := tx.ExecContext(ctx, `INSERT INTO exposure_listen (`+listenCols+`) VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)
		ON CONFLICT(address, proto, port) DO UPDATE SET state = 'open', service = excluded.service, bind = excluded.bind,
		owner = excluded.owner, last_seen = excluded.last_seen, source = excluded.source`,
		r.Address, r.Proto, r.Port, r.Service, r.Bind, r.Owner, ts, ts, r.Source); err != nil {
		return err
	}
	switch {
	case err == sql.ErrNoRows && !baseline, prev == "gone":
		return addEvent(ctx, tx, now, EventListenNew, r.Proto, r.Port, r.Address, r.Service)
	}
	return nil
}

// hasSeen sagt, ob die Adresse schon einmal aufgenommen wurde (sonst ist der naechste Aufruf ihre Baseline). Das gilt
// auch fuer ein Geraet ohne offene Ports: sein erster offener Port ist spaeter ein Ereignis.
func hasSeen(ctx context.Context, tx txer, address string) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM exposure_seen WHERE address = ?`, address).Scan(&n)
	return n > 0, err
}

// markSeen merkt die Adresse als aufgenommen.
func markSeen(ctx context.Context, tx txer, now time.Time, address string) error {
	_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO exposure_seen (address, at) VALUES (?, ?)`, address, store.FormatTime(now))
	return err
}

// recordSelf nimmt die lauschenden Ports der Node auf. Zeilen der Node, die in rows fehlen, gelten als "gone".
func (m *Module) recordSelf(ctx context.Context, now time.Time, rows []Listen) error {
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	existing, err := hasSeen(ctx, tx, SelfAddress)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, r := range rows {
		r.Address, r.Source = SelfAddress, "self"
		if err := upsert(ctx, tx, now, r, !existing); err != nil {
			return err
		}
		seen[portKey(r.Proto, r.Port)] = true
	}
	open, err := tx.QueryContext(ctx, `SELECT proto, port FROM exposure_listen WHERE address = ? AND state = 'open'`, SelfAddress)
	if err != nil {
		return err
	}
	var gone []Listen
	for open.Next() {
		var l Listen
		if err := open.Scan(&l.Proto, &l.Port); err != nil {
			open.Close()
			return err
		}
		if !seen[portKey(l.Proto, l.Port)] {
			gone = append(gone, l)
		}
	}
	open.Close()
	for _, l := range gone {
		if _, err := tx.ExecContext(ctx, `UPDATE exposure_listen SET state = 'gone' WHERE address = ? AND proto = ? AND port = ?`, SelfAddress, l.Proto, l.Port); err != nil {
			return err
		}
		if err := addEvent(ctx, tx, now, EventListenGone, l.Proto, l.Port, SelfAddress, ""); err != nil {
			return err
		}
	}
	if err := markSeen(ctx, tx, now, SelfAddress); err != nil {
		return err
	}
	return tx.Commit()
}

func portKey(proto string, port int) string { return proto + "/" + itoa(port) }

// recordHost nimmt das Ergebnis eines Scans auf. Antwortete das Geraet auf keinem Port (Reached ist falsch), ist es
// vermutlich aus, und es aendert sich nichts. Sonst werden offene Ports aufgenommen und bisher offene Ports, die jetzt
// zu oder gefiltert sind, "gone". Ports, die nicht gescannt wurden, bleiben unberuehrt.
func (m *Module) recordHost(ctx context.Context, now time.Time, ip netip.Addr, rs []PortResult) error {
	if !Reached(rs) {
		return nil
	}
	addr := ip.Unmap().WithZone("").String()
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	existing, err := hasSeen(ctx, tx, addr)
	if err != nil {
		return err
	}
	for _, r := range rs {
		if r.State == StateOpen {
			if err := upsert(ctx, tx, now, Listen{Address: addr, Proto: "tcp", Port: r.Port, Service: ServiceName("tcp", r.Port), Source: "scan"}, !existing); err != nil {
				return err
			}
			continue
		}
		res, err := tx.ExecContext(ctx, `UPDATE exposure_listen SET state = 'gone' WHERE address = ? AND proto = 'tcp' AND port = ? AND state = 'open'`, addr, r.Port)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			if err := addEvent(ctx, tx, now, EventListenGone, "tcp", r.Port, addr, ""); err != nil {
				return err
			}
		}
	}
	if err := markSeen(ctx, tx, now, addr); err != nil {
		return err
	}
	return tx.Commit()
}

// Listening liefert die gespeicherten Ports einer Adresse ("" = alle): erst die Node, dann die Geraete nach Adresse,
// je Adresse nach Protokoll und Port.
func (m *Module) Listening(ctx context.Context, address string) ([]Listen, error) {
	query := `SELECT ` + listenCols + ` FROM exposure_listen`
	var args []any
	if address != "" {
		query += ` WHERE address = ?`
		args = append(args, address)
	}
	rows, err := m.core.Reader().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Listen
	for rows.Next() {
		var l Listen
		var first, last string
		if err := rows.Scan(&l.Address, &l.Proto, &l.Port, &l.State, &l.Service, &l.Bind, &l.Owner, &first, &last, &l.Source); err != nil {
			return nil, err
		}
		l.FirstSeen, l.LastSeen = store.ParseTime(first), store.ParseTime(last)
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out, rows.Err()
}

// less: Node zuerst, dann Adressen numerisch, dann Protokoll, dann Port.
func less(a, b Listen) bool {
	if a.Address != b.Address {
		if a.Address == SelfAddress || b.Address == SelfAddress {
			return a.Address == SelfAddress
		}
		x, errX := netip.ParseAddr(a.Address)
		y, errY := netip.ParseAddr(b.Address)
		if errX == nil && errY == nil {
			return x.Compare(y) < 0
		}
		return a.Address < b.Address
	}
	if a.Proto != b.Proto {
		return a.Proto < b.Proto
	}
	return a.Port < b.Port
}

// Forget loescht die Zeilen einer Adresse (z. B. Geraet nicht mehr in IPAM).
func (m *Module) Forget(ctx context.Context, address string) error {
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"exposure_listen", "exposure_seen"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE address = ?`, address); err != nil {
			return err
		}
	}
	return tx.Commit()
}
