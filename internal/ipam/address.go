package ipam

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// seenWindow: so lange nach der letzten Sichtung gilt eine Adresse als belegt (ohne Scan gibt es keine feinere Messung).
const seenWindow = 24 * time.Hour

// maxLabel ist die laengste Bezeichnung (Name, Notiz) in Zeichen.
const maxLabel = 253

var (
	ErrInvalidMAC   = errors.New("ipam: invalid mac address")
	ErrInvalidLabel = errors.New("ipam: invalid text")
)

// Status ist der berechnete Zustand einer Adresse (nicht gespeichert).
type Status string

const (
	StatusUsed     Status = "used"     // in den letzten 24 Stunden gesehen
	StatusOffline  Status = "offline"  // frueher gesehen, jetzt nicht
	StatusReserved Status = "reserved" // reserviert und nicht gesehen
	StatusNew      Status = "new"      // gesehen, aber weder benannt noch bestaetigt noch ignoriert
)

// Address ist eine Zeile der Adressliste eines Subnetzes.
type Address struct {
	ID, SubnetID int64
	IP           netip.Addr
	Name         string // von Hand
	SourceName   string // aus einer Quelle (DNS64, ...)
	MAC          string // zuletzt gesehen
	ReservedMAC  string // von Hand gesetzt
	Note         string
	Reserved     bool
	Acknowledged bool
	Ignored      bool
	AutoKnown    bool // IPv6-Adresse einer MAC, die schon an einer bekannten Adresse haengt
	FirstSeen    time.Time
	LastSeen     time.Time
	LastSource   string
}

// DisplayName ist der Name von Hand, sonst der aus der Quelle.
func (a Address) DisplayName() string {
	if a.Name != "" {
		return a.Name
	}
	return a.SourceName
}

// Seen sagt, ob die Adresse innerhalb von seenWindow gesehen wurde.
func (a Address) Seen(now time.Time) bool {
	return !a.LastSeen.IsZero() && now.Sub(a.LastSeen) <= seenWindow
}

// isNew: weder reserviert noch bestaetigt, ignoriert, automatisch bekannt noch benannt.
func (a Address) isNew() bool {
	return !a.Reserved && !a.Acknowledged && !a.Ignored && !a.AutoKnown && a.Name == "" && a.SourceName == ""
}

// StatusAt berechnet den Zustand zum Zeitpunkt now. Ein unbekanntes Geraet bleibt "neu", bis der Nutzer es
// bestaetigt, ignoriert oder benennt - auch wenn es laengst offline ist (sonst verschwindet der Hinweis nach 24 Stunden).
func (a Address) StatusAt(now time.Time) Status {
	seen := a.Seen(now)
	switch {
	case !seen && a.Reserved:
		return StatusReserved
	case a.isNew() && !a.LastSeen.IsZero():
		return StatusNew
	case seen:
		return StatusUsed
	}
	return StatusOffline
}

// ConflictAt: eine von Hand gesetzte MAC der Reservierung, aber unter der Adresse wird eine andere gesehen.
func (a Address) ConflictAt(now time.Time) bool {
	return a.ReservedMAC != "" && a.MAC != "" && a.MAC != a.ReservedMAC && a.Seen(now)
}

// NormalizeMAC liefert die MAC in Kleinbuchstaben mit Doppelpunkten; leer bleibt leer. Alles null und Broadcast fallen weg.
func NormalizeMAC(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return "", ErrInvalidMAC
	}
	zero, ff := true, true
	for _, b := range hw {
		zero = zero && b == 0
		ff = ff && b == 0xff
	}
	if zero || ff {
		return "", ErrInvalidMAC
	}
	return hw.String(), nil
}

// NormalizeLabel trimmt eine Bezeichnung und lehnt Steuerzeichen und zu lange Texte ab. HTML bleibt erlaubt, die Seite escaped.
func NormalizeLabel(s string) (string, error) {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > maxLabel {
		return "", ErrInvalidLabel
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", ErrInvalidLabel
		}
	}
	return s, nil
}
