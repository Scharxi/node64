package ipam

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

var (
	ErrInvalidCIDR = errors.New("ipam: invalid network")
	ErrOverlap     = errors.New("ipam: network overlaps an existing one")
	ErrNotFound    = errors.New("ipam: not found")
)

// Grenzen fuer Subnetze (Plan: IPv4 /8 bis /32, IPv6 /48 bis /128).
const (
	minBits4, minBits6 = 8, 48
)

// Subnet ist ein angelegtes Netz.
type Subnet struct {
	ID         int64
	Name       string
	CIDR       netip.Prefix
	Note       string
	BaselineAt time.Time // erster Durchlauf, der das Netz gesehen hat (leer = noch keiner)
	CreatedAt  time.Time
}

// ParseSubnet prueft Name und Netz; das Netz wird maskiert (192.168.1.5/24 -> 192.168.1.0/24).
func ParseSubnet(name, cidr, note string) (Subnet, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || p.Addr().Is4In6() {
		return Subnet{}, ErrInvalidCIDR
	}
	minBits := minBits6
	if p.Addr().Is4() {
		minBits = minBits4
	}
	if p.Bits() < minBits {
		return Subnet{}, ErrInvalidCIDR
	}
	n, err := NormalizeLabel(name)
	if err != nil || n == "" {
		return Subnet{}, ErrInvalidLabel
	}
	nt, err := NormalizeLabel(note)
	if err != nil {
		return Subnet{}, err
	}
	return Subnet{Name: n, CIDR: p.Masked(), Note: nt}, nil
}

// Subnets liefert alle Netze, IPv4 vor IPv6, nach Adresse sortiert.
func (m *Module) Subnets(ctx context.Context) ([]Subnet, error) {
	return loadSubnets(ctx, m.core.Reader())
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func loadSubnets(ctx context.Context, q querier) ([]Subnet, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, name, cidr, note, baseline_at, created_at FROM ipam_subnets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Subnet
	for rows.Next() {
		var s Subnet
		var cidr, base, created string
		if err := rows.Scan(&s.ID, &s.Name, &cidr, &s.Note, &base, &created); err != nil {
			return nil, err
		}
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue // kaputte Zeile (von Hand geaendert) ueberspringen
		}
		s.CIDR, s.BaselineAt, s.CreatedAt = p, store.ParseTime(base), store.ParseTime(created)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].CIDR.Addr().Compare(out[j].CIDR.Addr()); c != 0 {
			return c < 0
		}
		return out[i].CIDR.Bits() < out[j].CIDR.Bits()
	})
	return out, rows.Err()
}

// AddSubnet legt ein Netz an; ErrOverlap, wenn es ein vorhandenes gleicht, umschliesst oder schneidet.
func (m *Module) AddSubnet(ctx context.Context, name, cidr, note string) (Subnet, error) {
	s, err := ParseSubnet(name, cidr, note)
	if err != nil {
		return Subnet{}, err
	}
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return Subnet{}, err
	}
	defer tx.Rollback()
	existing, err := loadSubnets(ctx, tx)
	if err != nil {
		return Subnet{}, err
	}
	for _, e := range existing {
		if e.CIDR.Overlaps(s.CIDR) {
			return Subnet{}, ErrOverlap
		}
	}
	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx, `INSERT INTO ipam_subnets (name, cidr, note, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		s.Name, s.CIDR.String(), s.Note, store.FormatTime(now), store.FormatTime(now))
	if err != nil {
		return Subnet{}, err
	}
	if s.ID, err = res.LastInsertId(); err != nil {
		return Subnet{}, err
	}
	s.CreatedAt = now
	return s, tx.Commit()
}

// DeleteSubnet loescht das Netz samt seinen Adressen in einer Transaktion.
func (m *Module) DeleteSubnet(ctx context.Context, id int64) error {
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM ipam_subnets WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ipam_addresses WHERE subnet_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// SubnetOf sucht das Netz, in dem die Adresse liegt (IPv4-in-IPv6 wird entpackt).
func SubnetOf(list []Subnet, ip netip.Addr) (Subnet, bool) {
	ip = ip.Unmap()
	for _, s := range list {
		if s.CIDR.Contains(ip) {
			return s, true
		}
	}
	return Subnet{}, false
}

// HostCount ist die Zahl der nutzbaren Adressen: IPv4 ohne Netz- und Broadcast-Adresse (/31 = 2, /32 = 1);
// IPv6 wird nicht gezaehlt (0).
func HostCount(p netip.Prefix) uint64 {
	if !p.Addr().Is4() {
		return 0
	}
	bits := 32 - p.Bits()
	switch bits {
	case 0:
		return 1
	case 1:
		return 2
	}
	return uint64(1)<<bits - 2
}
