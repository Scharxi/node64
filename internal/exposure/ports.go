package exposure

import (
	"errors"
	"sort"
	"strconv"
	"strings"
)

// maxPorts ist die Obergrenze fuer die Ports je Lauf (Standardliste plus eigene).
const maxPorts = 100

var (
	ErrInvalidPorts = errors.New("exposure: invalid port list")
	ErrTooManyPorts = errors.New("exposure: too many ports")
)

// defaultPorts sind haeufige TCP-Ports (Verwaltung, Dateien, Mail, Datenbanken, Smart Home, Web-Oberflaechen).
var defaultPorts = []int{
	21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 119, 123, 135, 139, 143, 161, 389, 443, 444, 445, 465, 500, 514, 515, 548, 554,
	587, 631, 636, 873, 990, 993, 995, 1080, 1194, 1433, 1521, 1723, 1883, 1900, 2049, 2082, 2083, 2222, 2375, 2376, 3000,
	3128, 3260, 3306, 3389, 3478, 4000, 4200, 4443, 5000, 5001, 5060, 5222, 5353, 5432, 5601, 5900, 5984, 6000, 6379, 6443,
	7000, 8000, 8008, 8080, 8081, 8086, 8088, 8123, 8200, 8443, 8444, 8500, 8883, 8888, 9000, 9090, 9100, 9200, 9443, 10000,
	11211, 27017, 32400,
}

// ParsePorts liest eigene Ports: Komma, Leerzeichen und Zeilenumbruch trennen, "8000-8010" ist ein Bereich. Das Ergebnis
// ist sortiert und ohne Duplikate. Ein Bereich ueber maxPorts Ports wird abgelehnt, bevor er aufgebaut wird.
func ParsePorts(s string) ([]int, error) {
	seen := map[int]bool{}
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ';' }) {
		lo, hi, isRange := strings.Cut(tok, "-")
		from, err := strconv.Atoi(lo)
		if err != nil {
			return nil, ErrInvalidPorts
		}
		to := from
		if isRange {
			if to, err = strconv.Atoi(hi); err != nil {
				return nil, ErrInvalidPorts
			}
		}
		if from < 1 || to > 65535 || from > to {
			return nil, ErrInvalidPorts
		}
		if to-from+1 > maxPorts {
			return nil, ErrTooManyPorts
		}
		for p := from; p <= to; p++ {
			seen[p] = true
		}
		if len(seen) > maxPorts {
			return nil, ErrTooManyPorts
		}
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

// ScanPorts ist die Liste eines Laufs: Standardliste plus eigene Ports, ohne Duplikate, sortiert, hoechstens maxPorts.
func ScanPorts(custom []int) ([]int, error) {
	seen := make(map[int]bool, len(defaultPorts)+len(custom))
	for _, p := range defaultPorts {
		seen[p] = true
	}
	for _, p := range custom {
		if p < 1 || p > 65535 {
			return nil, ErrInvalidPorts
		}
		seen[p] = true
	}
	if len(seen) > maxPorts {
		return nil, ErrTooManyPorts
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

var tcpServices = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc",
	139: "netbios", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog", 515: "lpd",
	548: "afp", 554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1433: "mssql",
	1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs", 2375: "docker", 2376: "docker-tls", 3306: "mysql", 3389: "rdp",
	5060: "sip", 5432: "postgres", 5900: "vnc", 5984: "couchdb", 6379: "redis", 6443: "kubernetes", 8080: "http-alt",
	8443: "https-alt", 8883: "mqtts", 9100: "jetdirect", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb", 32400: "plex",
}

var udpServices = map[int]string{53: "dns", 67: "dhcp", 123: "ntp", 161: "snmp", 500: "ike", 514: "syslog", 1194: "openvpn",
	1900: "ssdp", 5353: "mdns", 51820: "wireguard"}

// ServiceName liefert den gaengigen Namen eines Ports ("" = unbekannt).
func ServiceName(proto string, port int) string {
	if proto == "udp" {
		return udpServices[port]
	}
	return tcpServices[port]
}
