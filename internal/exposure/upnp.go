package exposure

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// UPnP-Client (Internet Gateway Device): fragt den Router nach der externen Adresse und den aktiven Port-Weiterleitungen.
// Der Router ist keine vertrauenswuerdige Quelle: Ziele werden vor jeder Anfrage geprueft, Antworten und Zahl der
// Eintraege sind begrenzt, Umleitungen werden nicht gefolgt.

var (
	// ErrUnsafeURL: die Adresse darf nicht angefragt werden (kein http/https, kein IP-Literal im privaten Bereich, anderer Host).
	ErrUnsafeURL = errors.New("exposure: unsafe url")
	// ErrNoService: die Beschreibung nennt keinen WAN-Verbindungsdienst.
	ErrNoService = errors.New("exposure: no WAN connection service found")
)

// Mapping ist eine aktive Port-Weiterleitung des Routers.
type Mapping struct {
	ExternalPort int
	Proto        string // tcp oder udp
	InternalAddr netip.Addr
	InternalPort int
	Description  string
}

// RouterInfo ist das Ergebnis einer Abfrage. Truncated: es gab mehr Weiterleitungen als MaxMappings.
type RouterInfo struct {
	ExternalIP netip.Addr
	Mappings   []Mapping
	Truncated  bool
}

// UPnPOptions begrenzen die Abfrage.
type UPnPOptions struct {
	HTTP        *http.Client
	MaxMappings int
	MaxBody     int64
	Overall     time.Duration // Zeitbudget der ganzen Abfrage (Beschreibung, externe Adresse, alle Weiterleitungen)
}

// DefaultUPnPOptions: 5 Sekunden je Anfrage, 60 Sekunden insgesamt, 256 Weiterleitungen, Antworten bis 1 MiB, kein Proxy.
func DefaultUPnPOptions() UPnPOptions {
	return UPnPOptions{HTTP: upnpClient(UPnPOptions{}), MaxMappings: 256, MaxBody: 1 << 20, Overall: 60 * time.Second}
}

// noProxyTransport: ein Weg ohne Proxy aus der Umgebung (HTTP_PROXY): sonst gingen die Anfragen an den Proxy statt an die
// geprueften Adresse des Routers.
func noProxyTransport() *http.Transport {
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Transport{Proxy: nil, DialContext: d.DialContext, ResponseHeaderTimeout: 5 * time.Second, MaxIdleConns: 2, IdleConnTimeout: 10 * time.Second}
}

// upnpClient liefert den Client der Abfrage: eine Kopie von o.HTTP (Zeitlimit 5 s, wenn keiner gegeben ist), ohne Umleitungen
// und, wenn kein eigener Transport gesetzt ist (Tests setzen einen), ohne Proxy.
func upnpClient(o UPnPOptions) *http.Client {
	c := &http.Client{Timeout: 5 * time.Second}
	if o.HTTP != nil {
		cp := *o.HTTP
		c = &cp
	}
	if c.Transport == nil {
		c.Transport = noProxyTransport()
	}
	c.CheckRedirect = noRedirect
	return c
}

// wanServices sind die Dienste, ueber die ein Router Weiterleitungen verwaltet.
var wanServices = map[string]bool{
	"urn:schemas-upnp-org:service:WANIPConnection:1":  true,
	"urn:schemas-upnp-org:service:WANIPConnection:2":  true,
	"urn:schemas-upnp-org:service:WANPPPConnection:1": true,
}

// SafeLocation prueft eine Adresse des Routers: http oder https, ein IP-Literal (kein Hostname, keine Zugangsdaten) im
// privaten Bereich oder Loopback. So kann ein Router (oder wer im LAN SSDP-Antworten faelscht) die Node nicht dazu
// bringen, Anfragen an Adressen im Internet zu schicken.
func SafeLocation(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return nil, ErrUnsafeURL
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ScanAllowed(addr) {
		return nil, ErrUnsafeURL
	}
	return u, nil
}

type xService struct {
	Type    string `xml:"serviceType"`
	Control string `xml:"controlURL"`
}

type xDevice struct {
	Services []xService `xml:"serviceList>service"`
	Devices  []xDevice  `xml:"deviceList>device"`
}

type xRoot struct {
	Device xDevice `xml:"device"`
}

// findService sucht in der Geraetebaumstruktur den ersten WAN-Verbindungsdienst.
func findService(d xDevice) (xService, bool) {
	for _, s := range d.Services {
		if wanServices[strings.TrimSpace(s.Type)] {
			return s, true
		}
	}
	for _, c := range d.Devices {
		if s, ok := findService(c); ok {
			return s, true
		}
	}
	return xService{}, false
}

// noRedirect: Umleitungen werden nicht gefolgt (die Antwort 3xx zaehlt als Fehler).
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// readLimited liest hoechstens max Bytes; mehr ist ein Fehler.
func readLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("response too large (limit %d bytes)", max)
	}
	return b, nil
}

// soapError ist ein Fehler des Routers (HTTP-Status und UPnP-Fehlercode, wenn vorhanden).
type soapError struct {
	Status int
	Code   string
}

func (e *soapError) Error() string {
	return fmt.Sprintf("router answered with status %d (upnp error %q)", e.Status, e.Code)
}

// soapFields liest die Blattelemente einer SOAP-Antwort (lokaler Name -> Text).
func soapFields(b []byte) map[string]string {
	out := map[string]string{}
	dec := xml.NewDecoder(bytes.NewReader(b))
	type frame struct {
		name     string
		text     strings.Builder
		children int
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err != nil {
			return out
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if n := len(stack); n > 0 {
				stack[n-1].children++
			}
			stack = append(stack, &frame{name: t.Name.Local})
		case xml.CharData:
			if n := len(stack); n > 0 {
				stack[n-1].text.Write(t)
			}
		case xml.EndElement:
			if n := len(stack); n > 0 {
				f := stack[n-1]
				stack = stack[:n-1]
				if f.children == 0 {
					out[f.name] = strings.TrimSpace(f.text.String())
				}
			}
		}
	}
}

// soap ruft eine Aktion des Routers auf. Nicht 200 ergibt *soapError.
func soap(ctx context.Context, c *http.Client, ctl *url.URL, serviceType, action, args string, max int64) (map[string]string, error) {
	body := `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:` +
		action + ` xmlns:u="` + serviceType + `">` + args + `</u:` + action + `></s:Body></s:Envelope>`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ctl.String(), strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+serviceType+`#`+action+`"`)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := readLimited(resp.Body, max)
	if err != nil {
		return nil, err
	}
	fields := soapFields(b)
	if resp.StatusCode != http.StatusOK {
		return nil, &soapError{Status: resp.StatusCode, Code: fields["errorCode"]}
	}
	return fields, nil
}

// cleanText entfernt Steuerzeichen und kuerzt auf max Zeichen (Beschreibungen des Routers sind fremder Text).
func cleanText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}

// QueryRouter fragt den Router unter der Beschreibungs-Adresse location nach externer Adresse und Weiterleitungen.
// Eine Liste endet mit dem UPnP-Fehler 713 (Index ausserhalb); jeder andere Fehler ist ein Fehler der Abfrage und
// darf nicht als "keine Weiterleitungen" gelten.
func QueryRouter(ctx context.Context, location string, o UPnPOptions) (RouterInfo, error) {
	base, err := SafeLocation(location)
	if err != nil {
		return RouterInfo{}, err
	}
	if o.MaxMappings <= 0 {
		o.MaxMappings = 256
	}
	if o.MaxBody <= 0 {
		o.MaxBody = 1 << 20
	}
	if o.Overall <= 0 {
		o.Overall = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, o.Overall)
	defer cancel()
	client := *upnpClient(o)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return RouterInfo{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return RouterInfo{}, err
	}
	desc, err := readLimited(resp.Body, o.MaxBody)
	resp.Body.Close()
	if err != nil {
		return RouterInfo{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return RouterInfo{}, fmt.Errorf("description: unexpected status %d", resp.StatusCode)
	}
	var root xRoot
	if err := xml.Unmarshal(desc, &root); err != nil {
		return RouterInfo{}, fmt.Errorf("description: %w", err)
	}
	svc, ok := findService(root.Device)
	if !ok {
		return RouterInfo{}, ErrNoService
	}
	ref, err := url.Parse(strings.TrimSpace(svc.Control))
	if err != nil {
		return RouterInfo{}, ErrUnsafeURL
	}
	ctl := base.ResolveReference(ref) // URLBase der Beschreibung zaehlt nicht: aufgeloest wird gegen die geprueften Adresse
	if _, err := SafeLocation(ctl.String()); err != nil || !strings.EqualFold(ctl.Host, base.Host) {
		return RouterInfo{}, ErrUnsafeURL
	}
	serviceType := strings.TrimSpace(svc.Type)

	var info RouterInfo
	if f, err := soap(ctx, &client, ctl, serviceType, "GetExternalIPAddress", "", o.MaxBody); err == nil {
		if a, err := netip.ParseAddr(f["NewExternalIPAddress"]); err == nil {
			info.ExternalIP = a.Unmap()
		}
	}
	for i := 0; i < o.MaxMappings; i++ {
		f, err := soap(ctx, &client, ctl, serviceType, "GetGenericPortMappingEntry",
			"<NewPortMappingIndex>"+strconv.Itoa(i)+"</NewPortMappingIndex>", o.MaxBody)
		var se *soapError
		if errors.As(err, &se) && se.Code == "713" {
			return info, nil // Ende der Liste
		}
		if err != nil {
			return RouterInfo{}, err
		}
		if m, ok := parseMapping(f); ok {
			info.Mappings = append(info.Mappings, m)
		}
	}
	info.Truncated = true
	return info, nil
}

// parseMapping uebernimmt einen Eintrag; ungueltige oder deaktivierte Eintraege fallen weg.
func parseMapping(f map[string]string) (Mapping, bool) {
	ext, errE := strconv.Atoi(f["NewExternalPort"])
	in, errI := strconv.Atoi(f["NewInternalPort"])
	proto := strings.ToLower(strings.TrimSpace(f["NewProtocol"]))
	addr, errA := netip.ParseAddr(strings.TrimSpace(f["NewInternalClient"]))
	if f["NewEnabled"] != "1" || errE != nil || errI != nil || errA != nil || (proto != "tcp" && proto != "udp") ||
		ext < 1 || ext > 65535 || in < 1 || in > 65535 {
		return Mapping{}, false
	}
	return Mapping{ExternalPort: ext, Proto: proto, InternalAddr: addr.Unmap(), InternalPort: in, Description: cleanText(f["NewPortMappingDescription"], 253)}, true
}
