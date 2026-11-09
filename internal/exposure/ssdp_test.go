package exposure

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func okResponse(loc string) []byte {
	return []byte("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nLOCATION: " + loc + "\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n")
}

func TestParseSSDPResponse(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
		ok   bool
	}{
		{"normal", okResponse("http://192.168.1.1:5000/rootDesc.xml"), "http://192.168.1.1:5000/rootDesc.xml", true},
		{"lower case header", []byte("HTTP/1.1 200 OK\r\nlocation:  http://192.168.1.1/d.xml \r\n\r\n"), "http://192.168.1.1/d.xml", true},
		{"mixed case header and LF only", []byte("HTTP/1.0 200 OK\nLocation: http://10.0.0.1/d.xml\n\n"), "http://10.0.0.1/d.xml", true},
		{"missing location", []byte("HTTP/1.1 200 OK\r\nST: x\r\n\r\n"), "", false},
		{"empty location", []byte("HTTP/1.1 200 OK\r\nLOCATION:\r\n\r\n"), "", false},
		{"status 500", []byte("HTTP/1.1 500 Error\r\nLOCATION: http://192.168.1.1/d.xml\r\n\r\n"), "", false},
		{"not http", []byte("garbage\r\nLOCATION: http://192.168.1.1/d.xml\r\n\r\n"), "", false},
		{"a request instead of a response", []byte("M-SEARCH * HTTP/1.1\r\nLOCATION: http://192.168.1.1/d.xml\r\n\r\n"), "", false},
		{"empty", nil, "", false},
	}
	for _, c := range cases {
		got, ok := ParseSSDPResponse(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: %q %v, want %q %v", c.name, got, ok, c.want, c.ok)
		}
	}
	// eine riesige Antwort wird nicht ausgewertet
	huge := append(okResponse("http://192.168.1.1/d.xml"), make([]byte, 20000)...)
	if _, ok := ParseSSDPResponse(huge); ok {
		t.Error("a response over the size limit must be dropped")
	}
}

func TestSSDPRequestFormat(t *testing.T) {
	r := string(ssdpRequest("urn:x"))
	if !strings.HasPrefix(r, "M-SEARCH * HTTP/1.1\r\n") || !strings.Contains(r, "HOST: 239.255.255.250:1900\r\n") ||
		!strings.Contains(r, "MAN: \"ssdp:discover\"\r\n") || !strings.Contains(r, "MX: 2\r\n") || !strings.Contains(r, "ST: urn:x\r\n") || !strings.HasSuffix(r, "\r\n\r\n") {
		t.Fatalf("request: %q", r)
	}
}

func TestSearchGatewaysDedupesAndSorts(t *testing.T) {
	o := DefaultSSDPOptions()
	o.Exchange = func(context.Context, [][]byte, time.Duration) ([]SSDPReply, error) {
		return []SSDPReply{{okResponse("http://192.168.1.2:80/b.xml"), netip.MustParseAddr("192.168.1.2")}, {okResponse("http://192.168.1.1:5000/a.xml"), netip.MustParseAddr("192.168.1.1")},
			{okResponse("http://192.168.1.2:80/b.xml"), netip.MustParseAddr("192.168.1.2")}, {[]byte("junk"), netip.MustParseAddr("192.168.1.9")}}, nil
	}
	got, err := SearchGateways(context.Background(), o)
	want := []string{"http://192.168.1.1:5000/a.xml", "http://192.168.1.2:80/b.xml"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v %v, want %v", got, err, want)
	}
}

func TestSearchGatewaysDropsUnsafeLocations(t *testing.T) {
	o := DefaultSSDPOptions()
	o.Exchange = func(context.Context, [][]byte, time.Duration) ([]SSDPReply, error) {
		a := netip.MustParseAddr("192.168.1.1")
		return []SSDPReply{{okResponse("http://8.8.8.8/d.xml"), a}, {okResponse("http://router.lan/d.xml"), a}, {okResponse("ftp://192.168.1.1/d.xml"), a}, {okResponse("http://192.168.1.1/d.xml"), a}}, nil
	}
	got, err := SearchGateways(context.Background(), o)
	if err != nil || len(got) != 1 || got[0] != "http://192.168.1.1/d.xml" {
		t.Fatalf("only the safe location stays: %v %v", got, err)
	}
}

func TestSearchGatewaysSendsBothTargets(t *testing.T) {
	var sent [][]byte
	o := DefaultSSDPOptions()
	o.Exchange = func(_ context.Context, p [][]byte, wait time.Duration) ([]SSDPReply, error) {
		sent = p
		if wait != 2*time.Second {
			t.Errorf("wait %v", wait)
		}
		return nil, nil
	}
	if _, err := SearchGateways(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	all := ""
	for _, p := range sent {
		all += string(p)
	}
	if len(sent) != 2 || !strings.Contains(all, "InternetGatewayDevice:1") || !strings.Contains(all, "InternetGatewayDevice:2") {
		t.Fatalf("payloads: %q", all)
	}
}

func TestSearchGatewaysExchangeError(t *testing.T) {
	o := DefaultSSDPOptions()
	boom := errors.New("no multicast")
	o.Exchange = func(context.Context, [][]byte, time.Duration) ([]SSDPReply, error) { return nil, boom }
	if _, err := SearchGateways(context.Background(), o); !errors.Is(err, boom) {
		t.Fatalf("error must pass through: %v", err)
	}
}

// Ein Geraet im LAN darf sich nicht als Router eines anderen Geraets ausgeben: die LOCATION muss auf den Absender zeigen.
func TestSearchGatewaysRequiresLocationFromResponder(t *testing.T) {
	o := DefaultSSDPOptions()
	o.Exchange = func(context.Context, [][]byte, time.Duration) ([]SSDPReply, error) {
		return []SSDPReply{
			{okResponse("http://192.168.1.254:49000/d.xml"), netip.MustParseAddr("192.168.1.100")}, // fremder Absender
			{okResponse("http://192.168.1.254:49000/d.xml"), netip.MustParseAddr("192.168.1.254")}, // der echte Router
			{okResponse("http://[fd00:64::1]:80/d.xml"), netip.MustParseAddr("fd00:64::1")},
			{okResponse("http://192.168.1.7/d.xml"), netip.Addr{}}, // Absender unbekannt: verworfen
		}, nil
	}
	got, err := SearchGateways(context.Background(), o)
	want := []string{"http://192.168.1.254:49000/d.xml", "http://[fd00:64::1]:80/d.xml"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v %v, want %v", got, err, want)
	}
}
