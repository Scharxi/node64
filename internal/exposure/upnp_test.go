package exposure

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeEntry ist eine Weiterleitung des Fake-Routers.
type fakeEntry struct {
	ExternalPort int
	Proto        string
	InternalPort int
	Client       string
	Enabled      string
	Description  string
}

// fakeIGD ist ein UPnP-Router zum Ausprobieren: Beschreibung unter /desc.xml, Steuerung unter /ctl.
type fakeIGD struct {
	srv       *httptest.Server
	entries   []fakeEntry
	endless   bool   // fuer jeden Index einen Eintrag
	external  string // Antwort auf GetExternalIPAddress
	controlTx string // Text von <controlURL> in der Beschreibung ("" = /ctl)
	fault     string // Fehlercode statt 713 am Ende der Liste ("" = 713)
	descPad   int    // so viele Bytes Fuellung in der Beschreibung
	delay     time.Duration
	soapDelay time.Duration // Verzoegerung je SOAP-Aufruf
	soapCalls atomic.Int64
	getCalls  atomic.Int64
}

var indexRe = regexp.MustCompile(`<NewPortMappingIndex>(\d+)</NewPortMappingIndex>`)

func newFakeIGD(t *testing.T, entries ...fakeEntry) *fakeIGD {
	t.Helper()
	f := &fakeIGD{entries: entries, external: "203.0.113.7"}
	mux := http.NewServeMux()
	mux.HandleFunc("/desc.xml", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(f.delay)
		ctl := f.controlTx
		if ctl == "" {
			ctl = "/ctl"
		}
		fmt.Fprintf(w, `<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><URLBase>http://8.8.8.8:80/</URLBase><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>%s</controlURL></service></serviceList></device></deviceList></device></deviceList></device></root>%s`, ctl, strings.Repeat(" ", f.descPad))
	})
	mux.HandleFunc("/nowan.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device><deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType></device></root>`)
	})
	mux.HandleFunc("/redirect.xml", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://8.8.8.8/x.xml", http.StatusFound)
	})
	mux.HandleFunc("/ctl", func(w http.ResponseWriter, r *http.Request) {
		f.soapCalls.Add(1)
		time.Sleep(f.soapDelay)
		body, _ := io.ReadAll(r.Body)
		action := r.Header.Get("SOAPAction")
		const st = "urn:schemas-upnp-org:service:WANIPConnection:1"
		switch {
		case strings.HasSuffix(action, `#GetExternalIPAddress"`):
			fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddressResponse xmlns:u="%s"><NewExternalIPAddress>%s</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`, st, f.external)
		case strings.HasSuffix(action, `#GetGenericPortMappingEntry"`):
			f.getCalls.Add(1)
			m := indexRe.FindSubmatch(body)
			idx := 0
			if m != nil {
				idx, _ = strconv.Atoi(string(m[1]))
			}
			var e fakeEntry
			switch {
			case f.endless:
				e = fakeEntry{ExternalPort: 1000 + idx, Proto: "TCP", InternalPort: 80, Client: "192.168.1.5", Enabled: "1"}
			case idx < len(f.entries):
				e = f.entries[idx]
			default:
				code := f.fault
				if code == "" {
					code = "713"
				}
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>%s</errorCode><errorDescription>x</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`, code)
				return
			}
			fmt.Fprintf(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetGenericPortMappingEntryResponse xmlns:u="%s"><NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>%s</NewProtocol><NewInternalPort>%d</NewInternalPort><NewInternalClient>%s</NewInternalClient><NewEnabled>%s</NewEnabled><NewPortMappingDescription>%s</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>`,
				st, e.ExternalPort, e.Proto, e.InternalPort, e.Client, e.Enabled, e.Description)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIGD) url(path string) string { return f.srv.URL + path }

// countingTransport zaehlt jede Anfrage, die hinausgeht.
type countingTransport struct{ n atomic.Int64 }

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return http.DefaultTransport.RoundTrip(r)
}

func testUPnPOptions() (UPnPOptions, *countingTransport) {
	ct := &countingTransport{}
	o := DefaultUPnPOptions()
	o.HTTP = &http.Client{Transport: ct, Timeout: 2 * time.Second}
	return o, ct
}

func TestSafeLocation(t *testing.T) {
	for _, ok := range []string{"http://192.168.1.1:5000/rootDesc.xml", "https://10.0.0.1/x", "http://127.0.0.1:1234/d.xml", "http://[fd00:64::1]:80/d.xml"} {
		if _, err := SafeLocation(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://8.8.8.8/x", "http://router.lan/x", "http://localhost/x", "ftp://127.0.0.1/x", "http://169.254.1.1/x", "http://[fe80::1]/x",
		"", "http://", "127.0.0.1/x", "http://user:pw@192.168.1.1/x", "http://[2001:db8::1]/x", "file:///etc/passwd", "javascript:alert(1)"} {
		if _, err := SafeLocation(bad); !errors.Is(err, ErrUnsafeURL) {
			t.Errorf("%q: err %v, want ErrUnsafeURL", bad, err)
		}
	}
}

func TestQueryRouterReadsMappings(t *testing.T) {
	f := newFakeIGD(t,
		fakeEntry{80, "TCP", 8080, "192.168.1.5", "1", "Webserver"},
		fakeEntry{51820, "udp", 51820, "192.168.1.6", "1", "WireGuard"},
		fakeEntry{22, "TCP", 22, "192.168.1.7", "1", ""})
	o, _ := testUPnPOptions()
	info, err := QueryRouter(context.Background(), f.url("/desc.xml"), o)
	if err != nil {
		t.Fatal(err)
	}
	if info.ExternalIP != netip.MustParseAddr("203.0.113.7") || info.Truncated || len(info.Mappings) != 3 {
		t.Fatalf("info: %+v", info)
	}
	m := info.Mappings[1]
	if m.ExternalPort != 51820 || m.Proto != "udp" || m.InternalAddr != netip.MustParseAddr("192.168.1.6") || m.InternalPort != 51820 || m.Description != "WireGuard" {
		t.Fatalf("mapping: %+v", m)
	}
	if info.Mappings[0].Proto != "tcp" {
		t.Fatalf("protocol must be lower case: %+v", info.Mappings[0])
	}
}

// Review Focus 4: seltsame Eintraege.
func TestQueryRouterSkipsOddEntries(t *testing.T) {
	long := strings.Repeat("x", 5000)
	f := newFakeIGD(t,
		fakeEntry{81, "TCP", 81, "192.168.1.5", "0", "deaktiviert"},
		fakeEntry{0, "TCP", 81, "192.168.1.5", "1", "port null"},
		fakeEntry{70000, "TCP", 81, "192.168.1.5", "1", "port gross"},
		fakeEntry{82, "ICMP", 82, "192.168.1.5", "1", "protokoll"},
		fakeEntry{83, "TCP", 83, "abc", "1", "adresse"},
		fakeEntry{84, "TCP", 0, "192.168.1.5", "1", "interner port null"},
		fakeEntry{85, "tcp", 85, "192.168.1.8", "1", long},
	)
	o, _ := testUPnPOptions()
	info, err := QueryRouter(context.Background(), f.url("/desc.xml"), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Mappings) != 1 || info.Mappings[0].ExternalPort != 85 {
		t.Fatalf("only the valid entry stays: %+v", info.Mappings)
	}
	if n := len([]rune(info.Mappings[0].Description)); n != 253 {
		t.Fatalf("long description is cut to 253 characters, got %d", n)
	}
}

// Review Focus 1: fremde Ziele werden abgelehnt, ohne dass eine Anfrage hinausgeht.
func TestQueryRouterRefusesUnsafeTargets(t *testing.T) {
	f := newFakeIGD(t, fakeEntry{80, "TCP", 80, "192.168.1.5", "1", ""})
	o, ct := testUPnPOptions()
	for _, bad := range []string{"http://8.8.8.8/desc.xml", "http://router.lan/desc.xml", "ftp://127.0.0.1/x", "http://169.254.1.1/x", "http://[fe80::1]/x"} {
		if _, err := QueryRouter(context.Background(), bad, o); !errors.Is(err, ErrUnsafeURL) {
			t.Errorf("%s: %v, want ErrUnsafeURL", bad, err)
		}
	}
	if ct.n.Load() != 0 || f.srv == nil {
		t.Fatalf("no request may leave for an unsafe location, got %d", ct.n.Load())
	}
	// Steuer-URL auf einen anderen Host, anderen Port, ein anderes Schema: keine SOAP-Anfrage
	for _, ctl := range []string{"http://8.8.8.8/ctl", "http://127.0.0.1:1/ctl", "ftp://127.0.0.1/ctl", "//example.com/ctl"} {
		f.controlTx = ctl
		before := f.soapCalls.Load()
		if _, err := QueryRouter(context.Background(), f.url("/desc.xml"), o); !errors.Is(err, ErrUnsafeURL) {
			t.Errorf("control %q: %v, want ErrUnsafeURL", ctl, err)
		}
		if f.soapCalls.Load() != before {
			t.Errorf("control %q: a SOAP request went out", ctl)
		}
	}
	// relative Steuer-URL funktioniert; URLBase der Beschreibung (hier 8.8.8.8) wird nicht zum Ziel
	f.controlTx = "ctl"
	if info, err := QueryRouter(context.Background(), f.url("/desc.xml"), o); err != nil || len(info.Mappings) != 1 {
		t.Fatalf("relative control url: %v %+v", err, info)
	}
}

func TestQueryRouterCapsEndlessMappings(t *testing.T) {
	f := newFakeIGD(t)
	f.endless = true
	o, _ := testUPnPOptions()
	o.MaxMappings = 10
	info, err := QueryRouter(context.Background(), f.url("/desc.xml"), o)
	if err != nil || len(info.Mappings) != 10 || !info.Truncated {
		t.Fatalf("cap: %v %d truncated=%v", err, len(info.Mappings), info.Truncated)
	}
	if f.getCalls.Load() > 10 {
		t.Fatalf("asked %d times, cap is 10", f.getCalls.Load())
	}
}

func TestQueryRouterBodyLimit(t *testing.T) {
	f := newFakeIGD(t)
	f.descPad = 5000
	o, _ := testUPnPOptions()
	o.MaxBody = 1000
	if _, err := QueryRouter(context.Background(), f.url("/desc.xml"), o); err == nil {
		t.Fatal("a description over the limit must fail")
	}
}

func TestQueryRouterTimeout(t *testing.T) {
	f := newFakeIGD(t)
	f.delay = 400 * time.Millisecond
	o, _ := testUPnPOptions()
	o.HTTP.Timeout = 50 * time.Millisecond
	start := time.Now()
	if _, err := QueryRouter(context.Background(), f.url("/desc.xml"), o); err == nil {
		t.Fatal("a hanging router must fail")
	}
	if time.Since(start) > 300*time.Millisecond {
		t.Fatalf("took %v", time.Since(start))
	}
}

func TestQueryRouterRefusesRedirect(t *testing.T) {
	f := newFakeIGD(t)
	o, ct := testUPnPOptions()
	if _, err := QueryRouter(context.Background(), f.url("/redirect.xml"), o); err == nil {
		t.Fatal("a redirect must not be followed")
	}
	if ct.n.Load() != 1 {
		t.Fatalf("exactly one request (the original), got %d", ct.n.Load())
	}
}

func TestQueryRouterNoService(t *testing.T) {
	f := newFakeIGD(t)
	o, _ := testUPnPOptions()
	if _, err := QueryRouter(context.Background(), f.url("/nowan.xml"), o); !errors.Is(err, ErrNoService) {
		t.Fatalf("no WAN service: %v", err)
	}
}

// Ein Fehler, der nicht "Index zu gross" (713) ist, darf nicht als "keine Weiterleitungen" gelten.
func TestQueryRouterOtherFaultIsError(t *testing.T) {
	f := newFakeIGD(t)
	f.fault = "501"
	o, _ := testUPnPOptions()
	if _, err := QueryRouter(context.Background(), f.url("/desc.xml"), o); err == nil {
		t.Fatal("fault 501 must be an error, not an empty list")
	}
	f.fault = ""
	info, err := QueryRouter(context.Background(), f.url("/desc.xml"), o)
	if err != nil || len(info.Mappings) != 0 {
		t.Fatalf("713 on index 0 is a valid empty list: %v %+v", err, info)
	}
}

// Zeitbudget (Review): ein Router, der Antwort um Antwort tropft, haelt den Lauf nicht minutenlang fest.
func TestQueryRouterOverallBudget(t *testing.T) {
	f := newFakeIGD(t)
	f.endless = true
	f.soapDelay = 100 * time.Millisecond
	o, _ := testUPnPOptions()
	o.HTTP.Timeout = 5 * time.Second
	o.Overall = 300 * time.Millisecond
	start := time.Now()
	info, err := QueryRouter(context.Background(), f.url("/desc.xml"), o)
	if err == nil {
		t.Fatalf("an endless slow router must hit the budget, got %d mappings", len(info.Mappings))
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("took %v", time.Since(start))
	}
	if len(info.Mappings) != 0 {
		t.Fatalf("a failed query returns nothing: %+v", info)
	}
	if DefaultUPnPOptions().Overall != 60*time.Second {
		t.Fatalf("default budget: %v", DefaultUPnPOptions().Overall)
	}
}

// Review: kein Umweg ueber einen Proxy aus der Umgebung (HTTP_PROXY): sonst gaelte "nur die geprueften Adresse" nicht mehr.
func TestUPnPClientIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:3128")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:3128")
	for name, o := range map[string]UPnPOptions{"default": DefaultUPnPOptions(), "bare client": {HTTP: &http.Client{Timeout: time.Second}}, "no client": {}} {
		c := upnpClient(o)
		tr, ok := c.Transport.(*http.Transport)
		if !ok || tr.Proxy != nil {
			t.Errorf("%s: the transport must not use a proxy: %#v", name, c.Transport)
		}
		if c.CheckRedirect == nil {
			t.Errorf("%s: redirects must be refused", name)
		}
	}
	// ein eigener Transport (Tests) bleibt, wie er ist
	ct := &countingTransport{}
	if c := upnpClient(UPnPOptions{HTTP: &http.Client{Transport: ct}}); c.Transport != http.RoundTripper(ct) {
		t.Error("a custom transport must be kept")
	}
}
