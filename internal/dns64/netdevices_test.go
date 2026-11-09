package dns64

import (
	"testing"
	"time"
)

// IPAM braucht MAC und letzte Sichtung des Geraets (additive Felder, Name und IP wie bisher).
func TestNetDeviceOf(t *testing.T) {
	last := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	d := netDeviceOf(deviceView{IP: "192.168.1.5", Name: "nas", MAC: "aa:bb:cc:00:00:05", Last: last, Host: true})
	if d.IP != "192.168.1.5" || d.Name != "nas" || d.MAC != "aa:bb:cc:00:00:05" || !d.LastSeen.Equal(last) {
		t.Fatalf("device: %+v", d)
	}
}
