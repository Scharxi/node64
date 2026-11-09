package ipam

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

var (
	ErrOutsideSubnet = errors.New("ipam: address is outside the subnet")
	ErrExists        = errors.New("ipam: address already exists")
	ErrInvalidIP     = errors.New("ipam: invalid ip address")
)

// AddressEdit sind die Felder, die man von Hand setzt.
type AddressEdit struct {
	Name, Note, ReservedMAC string
	Reserved                bool
}

// Addresses liefert die Adressen eines Subnetzes, nach Adresse numerisch sortiert.
func (m *Module) Addresses(ctx context.Context, subnetID int64) ([]Address, error) {
	return loadAddresses(ctx, m.core.Reader(), subnetID)
}

// check prueft und normalisiert die Eingaben; Name und Notiz getrimmt, MAC klein mit Doppelpunkten.
func (e AddressEdit) check() (AddressEdit, error) {
	var err error
	if e.Name, err = NormalizeLabel(e.Name); err != nil {
		return e, err
	}
	if e.Note, err = NormalizeLabel(e.Note); err != nil {
		return e, err
	}
	e.ReservedMAC, err = NormalizeMAC(e.ReservedMAC)
	return e, err
}

// AddAddress legt eine Adresse von Hand an (gilt sofort als bestaetigt).
func (m *Module) AddAddress(ctx context.Context, subnetID int64, ip string, e AddressEdit) (Address, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Address{}, ErrInvalidIP
	}
	addr = addr.Unmap()
	if e, err = e.check(); err != nil {
		return Address{}, err
	}
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return Address{}, err
	}
	defer tx.Rollback()
	subs, err := loadSubnets(ctx, tx)
	if err != nil {
		return Address{}, err
	}
	var sub *Subnet
	for i := range subs {
		if subs[i].ID == subnetID {
			sub = &subs[i]
		}
	}
	if sub == nil {
		return Address{}, ErrNotFound
	}
	if !sub.CIDR.Contains(addr) {
		return Address{}, ErrOutsideSubnet
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM ipam_addresses WHERE subnet_id = ? AND ip = ?`, subnetID, addr.String()).Scan(&n); err != nil {
		return Address{}, err
	}
	if n > 0 {
		return Address{}, ErrExists
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO ipam_addresses (subnet_id, ip, name, note, reserved, reserved_mac, acknowledged, last_source, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`, subnetID, addr.String(), e.Name, e.Note, boolInt(e.Reserved), e.ReservedMAC, SourceManual, store.Now())
	if err != nil {
		return Address{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Address{}, err
	}
	a, err := addressByID(ctx, tx, id)
	if err != nil {
		return Address{}, err
	}
	return a, tx.Commit()
}

// UpdateAddress setzt Name, Notiz und Reservierung (leere Werte loeschen sie); die Adresse gilt danach als bestaetigt.
func (m *Module) UpdateAddress(ctx context.Context, id int64, e AddressEdit) (Address, error) {
	e, err := e.check()
	if err != nil {
		return Address{}, err
	}
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return Address{}, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE ipam_addresses SET name = ?, note = ?, reserved = ?, reserved_mac = ?, acknowledged = 1 WHERE id = ?`,
		e.Name, e.Note, boolInt(e.Reserved), e.ReservedMAC, id)
	if err != nil {
		return Address{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Address{}, ErrNotFound
	}
	a, err := addressByID(ctx, tx, id)
	if err != nil {
		return Address{}, err
	}
	return a, tx.Commit()
}

// setFlag aendert eine Spalte einer Adresse; ErrNotFound, wenn es die Zeile nicht gibt.
func (m *Module) setFlag(ctx context.Context, id int64, column string, on bool) error {
	res, err := m.core.Writer().ExecContext(ctx, `UPDATE ipam_addresses SET `+column+` = ? WHERE id = ?`, boolInt(on), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Acknowledge bestaetigt eine Adresse (sie ist nicht mehr "neu").
func (m *Module) Acknowledge(ctx context.Context, id int64) error {
	return m.setFlag(ctx, id, "acknowledged", true)
}

// SetIgnored schaltet "ignoriert" ein oder aus (ignorierte Adressen werden nie "neu").
func (m *Module) SetIgnored(ctx context.Context, id int64, on bool) error {
	return m.setFlag(ctx, id, "ignored", on)
}

// AcknowledgeAll bestaetigt alle Adressen des Netzes, die gerade "neu" sind; Rueckgabe: ihre Zahl.
func (m *Module) AcknowledgeAll(ctx context.Context, subnetID int64) (int, error) {
	return m.acknowledgeAll(ctx, subnetID, time.Now().UTC())
}

func (m *Module) acknowledgeAll(ctx context.Context, subnetID int64, now time.Time) (int, error) {
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	list, err := loadAddresses(ctx, tx, subnetID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, a := range list {
		if a.StatusAt(now) != StatusNew {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE ipam_addresses SET acknowledged = 1 WHERE id = ?`, a.ID); err != nil {
			return 0, err
		}
		n++
	}
	return n, tx.Commit()
}

// DeleteAddress loescht eine Zeile (eine noch sichtbare Adresse taucht bei der naechsten Sichtung wieder auf).
func (m *Module) DeleteAddress(ctx context.Context, id int64) error {
	res, err := m.core.Writer().ExecContext(ctx, `DELETE FROM ipam_addresses WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SubnetStats sind die Zahlen einer Karte. Used: in den letzten 24 Stunden gesehen; Reserved: als reserviert
// eingetragen (auch wenn gesehen); New: unbekannte Geraete; Size: nutzbare IPv4-Adressen (IPv6: 0).
type SubnetStats struct {
	Size                           uint64
	Used, Reserved, New, Conflicts int
}

// Stats zaehlt je Subnetz zum Zeitpunkt now.
func (m *Module) Stats(ctx context.Context, now time.Time) (map[int64]SubnetStats, error) {
	subs, err := m.Subnets(ctx)
	if err != nil {
		return nil, err
	}
	addrs, err := loadAddresses(ctx, m.core.Reader(), 0)
	if err != nil {
		return nil, err
	}
	out := make(map[int64]SubnetStats, len(subs))
	for _, s := range subs {
		out[s.ID] = SubnetStats{Size: HostCount(s.CIDR)}
	}
	for _, a := range addrs {
		st, ok := out[a.SubnetID]
		if !ok {
			continue
		}
		if a.Seen(now) {
			st.Used++
		}
		if a.Reserved {
			st.Reserved++
		}
		if a.StatusAt(now) == StatusNew {
			st.New++
		}
		if a.ConflictAt(now) {
			st.Conflicts++
		}
		out[a.SubnetID] = st
	}
	return out, nil
}
