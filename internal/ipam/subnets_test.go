package ipam

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestParseSubnet(t *testing.T) {
	s, err := ParseSubnet("Heim", "192.168.1.5/24", "n")
	if err != nil || s.CIDR.String() != "192.168.1.0/24" || s.Name != "Heim" || s.Note != "n" {
		t.Fatalf("masked: %+v %v", s, err)
	}
	for _, in := range []string{"10.0.0.0/7", "10.0.0.0/33", "fd00::/47", "garbage", "", "10.0.0.0"} {
		if _, err := ParseSubnet("x", in, ""); !errors.Is(err, ErrInvalidCIDR) {
			t.Errorf("%q: err %v, want ErrInvalidCIDR", in, err)
		}
	}
	for _, in := range []string{"10.0.0.0/8", "10.0.0.1/32", "fd00:64::/64", "fd00:64::1/128", "fd00::/48"} {
		if _, err := ParseSubnet("x", in, ""); err != nil {
			t.Errorf("%q: %v", in, err)
		}
	}
	if _, err := ParseSubnet("  ", "192.168.1.0/24", ""); !errors.Is(err, ErrInvalidLabel) {
		t.Errorf("empty name: %v", err)
	}
}

func TestAddSubnetOverlap(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	mustSubnet(t, m, "Heim", "192.168.1.0/24")
	for _, in := range []string{"192.168.1.0/24", "192.168.1.128/25", "192.168.0.0/16"} {
		if _, err := m.AddSubnet(ctx, "x", in, ""); !errors.Is(err, ErrOverlap) {
			t.Errorf("%s: err %v, want ErrOverlap", in, err)
		}
	}
	mustSubnet(t, m, "Gaeste", "192.168.2.0/24")
	mustSubnet(t, m, "ULA", "fd00:64::/64") // IPv4 und IPv6 ueberlappen nie
	list, err := m.Subnets(ctx)
	if err != nil || len(list) != 3 {
		t.Fatalf("list: %d %v", len(list), err)
	}
	if list[0].CIDR.String() != "192.168.1.0/24" || list[1].CIDR.String() != "192.168.2.0/24" || list[2].CIDR.String() != "fd00:64::/64" {
		t.Fatalf("order: %v %v %v", list[0].CIDR, list[1].CIDR, list[2].CIDR)
	}
}

func TestDeleteSubnetRemovesAddresses(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	s := mustSubnet(t, m, "Heim", "192.168.1.0/24")
	if _, err := m.core.Writer().ExecContext(ctx, `INSERT INTO ipam_addresses (subnet_id, ip, created_at) VALUES (?, '192.168.1.5', 'x')`, s.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteSubnet(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = m.core.Reader().QueryRowContext(ctx, `SELECT count(*) FROM ipam_addresses`).Scan(&n)
	if n != 0 {
		t.Fatalf("addresses left: %d", n)
	}
	if err := m.DeleteSubnet(ctx, s.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func TestSubnetOf(t *testing.T) {
	list := []Subnet{
		{ID: 1, CIDR: netip.MustParsePrefix("192.168.1.0/24")},
		{ID: 2, CIDR: netip.MustParsePrefix("fd00:64::/64")},
	}
	for ip, want := range map[string]int64{"192.168.1.5": 1, "::ffff:192.168.1.9": 1, "fd00:64::7": 2} {
		s, ok := SubnetOf(list, netip.MustParseAddr(ip))
		if !ok || s.ID != want {
			t.Errorf("%s: %v %v, want subnet %d", ip, s.ID, ok, want)
		}
	}
	if _, ok := SubnetOf(list, netip.MustParseAddr("10.0.0.1")); ok {
		t.Error("10.0.0.1 must be outside")
	}
}

func TestHostCount(t *testing.T) {
	for in, want := range map[string]uint64{"192.168.1.0/24": 254, "10.0.0.0/30": 2, "10.0.0.0/31": 2, "10.0.0.1/32": 1, "10.0.0.0/8": 16777214, "fd00:64::/64": 0} {
		if got := HostCount(netip.MustParsePrefix(in)); got != want {
			t.Errorf("%s: %d, want %d", in, got, want)
		}
	}
}
