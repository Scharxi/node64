package ipam

import (
	"context"
	"net/netip"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// Quellen einer Beobachtung (Address.LastSource).
const (
	SourceDNS64    = "dns64"
	SourceNeighbor = "neighbor"
	SourceManual   = "manual"
)

// Aufraeumfristen fuer Adressen, die nur gesehen und nie von Hand angefasst wurden.
const (
	keepSeen4 = 90 * 24 * time.Hour
	keepSeen6 = 7 * 24 * time.Hour // rotierende Privacy-Adressen
)

// Observation ist eine Sichtung einer Adresse durch eine Quelle.
type Observation struct {
	IP     netip.Addr
	MAC    string // leer = unbekannt
	Name   string // Name aus der Quelle, leer = keiner
	Source string
	Seen   time.Time // leer = jetzt
}

// IngestResult fasst einen Durchlauf zusammen: Adressen ausserhalb aller Subnetze, neue unbekannte Geraete
// (ohne die Baseline des ersten Durchlaufs je Netz) und Adressen mit Konflikt.
type IngestResult struct{ Outside, New, Conflicts int }

// Ingest nimmt Beobachtungen auf, alles in einer Transaktion. Regeln: siehe docs/PLAN-NODE64-IPAM.md
// (Handeingabe schlaegt Quelle; erster Durchlauf je Netz ist die Baseline; IPv6 mit bekannter MAC gilt als bekannt).
func (m *Module) Ingest(ctx context.Context, now time.Time, obs []Observation) (IngestResult, error) {
	var res IngestResult
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return res, err
	}
	defer tx.Rollback()
	subnets, err := loadSubnets(ctx, tx)
	if err != nil {
		return res, err
	}
	rows, err := loadAddresses(ctx, tx, 0)
	if err != nil {
		return res, err
	}
	type key struct {
		sub int64
		ip  netip.Addr
	}
	byKey := make(map[key]*Address, len(rows))
	type macKey struct {
		sub int64
		mac string
	}
	macKnown := map[macKey]bool{} // (Subnetz, MAC) -> haengt an einer bekannten Adresse
	known := func(a *Address) bool {
		return a.Name != "" || a.SourceName != "" || a.Reserved || a.Acknowledged || a.Ignored || a.AutoKnown
	}
	for i := range rows {
		a := &rows[i]
		byKey[key{a.SubnetID, a.IP}] = a
		if a.MAC != "" && known(a) {
			macKnown[macKey{a.SubnetID, a.MAC}] = true
		}
	}
	baseline := map[int64]bool{} // Netze, deren Baseline in diesem Aufruf entsteht
	for _, s := range subnets {
		if s.BaselineAt.IsZero() {
			baseline[s.ID] = true
		}
	}
	touched := map[int64]bool{} // Netze, die in diesem Aufruf etwas gesehen haben
	outside := map[netip.Addr]bool{}
	changed := map[*Address]bool{}
	created := map[*Address]bool{}

	for _, o := range obs {
		ip := o.IP.Unmap()
		if !ip.IsValid() || (ip.Is6() && ip.IsLinkLocalUnicast()) {
			continue
		}
		sub, ok := SubnetOf(subnets, ip)
		if !ok {
			outside[ip] = true
			continue
		}
		touched[sub.ID] = true
		mac, err := NormalizeMAC(o.MAC)
		if err != nil {
			mac = ""
		}
		name, err := NormalizeLabel(o.Name)
		if err != nil {
			name = ""
		}
		seen := o.Seen
		if seen.IsZero() {
			seen = now
		}
		seen = seen.UTC()
		a := byKey[key{sub.ID, ip}]
		if a == nil {
			a = &Address{SubnetID: sub.ID, IP: ip, MAC: mac, SourceName: name, FirstSeen: seen, LastSeen: seen, LastSource: o.Source}
			if ip.Is6() && mac != "" && macKnown[macKey{sub.ID, mac}] {
				a.AutoKnown = true
			}
			byKey[key{sub.ID, ip}] = a
			created[a] = true
		} else {
			if a.FirstSeen.IsZero() {
				a.FirstSeen = seen
			}
			if !seen.Before(a.LastSeen) {
				a.LastSeen, a.LastSource = seen, o.Source
			}
			if mac != "" {
				a.MAC = mac
			}
			if name != "" {
				a.SourceName = name
			}
		}
		changed[a] = true
		if a.MAC != "" && known(a) {
			macKnown[macKey{sub.ID, a.MAC}] = true
		}
	}

	for a := range changed {
		if created[a] {
			if !baseline[a.SubnetID] && !a.AutoKnown && a.SourceName == "" {
				res.New++
			}
			r, err := tx.ExecContext(ctx, `INSERT INTO ipam_addresses (subnet_id, ip, source_name, mac, auto_known, first_seen, last_seen, last_source, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, a.SubnetID, a.IP.String(), a.SourceName, a.MAC, boolInt(a.AutoKnown),
				store.FormatTime(a.FirstSeen), store.FormatTime(a.LastSeen), a.LastSource, store.FormatTime(now))
			if err != nil {
				return res, err
			}
			if a.ID, err = r.LastInsertId(); err != nil {
				return res, err
			}
		} else if _, err := tx.ExecContext(ctx, `UPDATE ipam_addresses SET source_name = ?, mac = ?, first_seen = ?, last_seen = ?, last_source = ? WHERE id = ?`,
			a.SourceName, a.MAC, store.FormatTime(a.FirstSeen), store.FormatTime(a.LastSeen), a.LastSource, a.ID); err != nil {
			return res, err
		}
		if a.ConflictAt(now) {
			res.Conflicts++
		}
	}
	for id := range touched {
		if baseline[id] {
			if _, err := tx.ExecContext(ctx, `UPDATE ipam_subnets SET baseline_at = ? WHERE id = ?`, store.FormatTime(now), id); err != nil {
				return res, err
			}
		}
	}
	res.Outside = len(outside)
	return res, tx.Commit()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Cleanup loescht Adressen, die nur gesehen und nie von Hand angefasst wurden (kein Name, keine Notiz, nicht
// reserviert, bestaetigt oder ignoriert) und laenger nicht mehr: IPv4 nach 90 Tagen, IPv6 nach 7. Von Hand
// angelegte Zeilen ohne Sichtung bleiben. Rueckgabe: Zahl der geloeschten Zeilen.
func (m *Module) Cleanup(ctx context.Context, now time.Time) (int, error) {
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id, ip, last_seen FROM ipam_addresses
		WHERE name = '' AND note = '' AND reserved = 0 AND acknowledged = 0 AND ignored = 0 AND last_seen != ''`)
	if err != nil {
		return 0, err
	}
	var gone []int64
	for rows.Next() {
		var id int64
		var ip, last string
		if err := rows.Scan(&id, &ip, &last); err != nil {
			rows.Close()
			return 0, err
		}
		a, perr := netip.ParseAddr(ip)
		seen := store.ParseTime(last)
		if perr != nil || seen.IsZero() {
			continue
		}
		keep := keepSeen4
		if a.Is6() {
			keep = keepSeen6
		}
		if now.Sub(seen) > keep {
			gone = append(gone, id)
		}
	}
	rows.Close()
	for _, id := range gone {
		if _, err := tx.ExecContext(ctx, `DELETE FROM ipam_addresses WHERE id = ?`, id); err != nil {
			return 0, err
		}
	}
	return len(gone), tx.Commit()
}
