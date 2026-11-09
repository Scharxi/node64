package ipam

import (
	"context"
	"net/netip"
	"sort"

	"github.com/ipv64net/node64/internal/store"
)

const addrCols = `id, subnet_id, ip, name, source_name, mac, reserved_mac, note, reserved, acknowledged, ignored, auto_known, first_seen, last_seen, last_source`

// loadAddresses liest die Adressen eines Subnetzes (subnetID 0 = alle), nach Netz und Adresse numerisch sortiert.
func loadAddresses(ctx context.Context, q querier, subnetID int64) ([]Address, error) {
	if subnetID != 0 {
		return queryAddresses(ctx, q, ` WHERE subnet_id = ?`, subnetID)
	}
	return queryAddresses(ctx, q, ``)
}

// addressByID liest eine Zeile; ErrNotFound, wenn es sie nicht gibt.
func addressByID(ctx context.Context, q querier, id int64) (Address, error) {
	list, err := queryAddresses(ctx, q, ` WHERE id = ?`, id)
	if err != nil {
		return Address{}, err
	}
	if len(list) == 0 {
		return Address{}, ErrNotFound
	}
	return list[0], nil
}

func queryAddresses(ctx context.Context, q querier, where string, args ...any) ([]Address, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+addrCols+` FROM ipam_addresses`+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Address
	for rows.Next() {
		var a Address
		var ip, first, last string
		var res, ack, ign, auto int
		if err := rows.Scan(&a.ID, &a.SubnetID, &ip, &a.Name, &a.SourceName, &a.MAC, &a.ReservedMAC, &a.Note, &res, &ack, &ign, &auto, &first, &last, &a.LastSource); err != nil {
			return nil, err
		}
		if a.IP, err = netip.ParseAddr(ip); err != nil {
			continue // kaputte Zeile (von Hand geaendert) ueberspringen
		}
		a.Reserved, a.Acknowledged, a.Ignored, a.AutoKnown = res == 1, ack == 1, ign == 1, auto == 1
		a.FirstSeen, a.LastSeen = store.ParseTime(first), store.ParseTime(last)
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SubnetID != out[j].SubnetID {
			return out[i].SubnetID < out[j].SubnetID
		}
		return out[i].IP.Compare(out[j].IP) < 0
	})
	return out, rows.Err()
}
