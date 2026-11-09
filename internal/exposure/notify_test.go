package exposure

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/notify"
)

// alertLog sammelt die Meldungen des Moduls.
type alertLog struct {
	mu sync.Mutex
	a  []notify.Alert
}

func (l *alertLog) add(a notify.Alert) { l.mu.Lock(); l.a = append(l.a, a); l.mu.Unlock() }
func (l *alertLog) all() []notify.Alert {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]notify.Alert(nil), l.a...)
}

func notifyModule(t *testing.T, s Settings) (*Module, *alertLog) {
	t.Helper()
	m := newTestModule(t)
	log := &alertLog{}
	m.SetNotifier(log.add)
	s.IntervalHours, s.KeepDays = 24, 90
	if err := m.saveRaw(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	return m, log
}

func fwd(port int, addr string) External {
	return External{Proto: "tcp", Port: port, InternalAddr: addr, InternalPort: port}
}

func TestNotifySettingsDefaults(t *testing.T) {
	m := newTestModule(t)
	s := m.LoadSettings(context.Background())
	if !s.NotifyUnexpected || s.NotifyNew || s.NotifyListen {
		t.Fatalf("defaults: unexpected on, new and listen off: %+v", s)
	}
}

func TestNotifyUnexpectedForward(t *testing.T) {
	m, log := notifyModule(t, Settings{NotifyUnexpected: true})
	ctx := context.Background()
	_ = m.recordExternal(ctx, t0, EvidenceUPnP, []External{fwd(22, "192.168.1.60")})
	if err := m.notifyChanges(ctx); err != nil {
		t.Fatal(err)
	}
	got := log.all()
	if len(got) != 1 || got[0].Kind != notify.KindExposureUnexpected || !got[0].Check.Local || got[0].Check.Name != "tcp/22" || got[0].Data["count"] != "1" ||
		got[0].Data["text"] != "notify.text.exposure_unexpected" || !strings.Contains(got[0].Data["list"], "192.168.1.60:22") || got[0].EventID == "" {
		t.Fatalf("alert: %+v", got)
	}
	// ein zweiter Lauf meldet nichts nach
	_ = m.notifyChanges(ctx)
	if len(log.all()) != 1 {
		t.Fatal("a processed event is never reported twice")
	}
}

func TestNotifyExpectedNewOnlyWhenEnabled(t *testing.T) {
	for _, on := range []bool{false, true} {
		m, log := notifyModule(t, Settings{NotifyUnexpected: true, NotifyNew: on})
		ctx := context.Background()
		_ = m.AddExpected(ctx, "tcp", 443, "Web")
		_ = m.recordExternal(ctx, t0, EvidenceUPnP, []External{fwd(443, "192.168.1.5")})
		_ = m.notifyChanges(ctx)
		got := log.all()
		if on && (len(got) != 1 || got[0].Kind != notify.KindExposureNew) {
			t.Fatalf("on: %+v", got)
		}
		if !on && len(got) != 0 {
			t.Fatalf("off: %+v", got)
		}
	}
}

func TestNotifyUnexpectedNeverAlsoNew(t *testing.T) {
	m, log := notifyModule(t, Settings{NotifyUnexpected: true, NotifyNew: true})
	ctx := context.Background()
	_ = m.recordExternal(ctx, t0, EvidenceUPnP, []External{fwd(22, "192.168.1.60")})
	_ = m.notifyChanges(ctx)
	if got := log.all(); len(got) != 1 || got[0].Kind != notify.KindExposureUnexpected {
		t.Fatalf("an unexpected forward triggers only the unexpected kind: %+v", got)
	}
}

func TestNotifyUnexpectedCanBeSwitchedOff(t *testing.T) {
	m, log := notifyModule(t, Settings{NotifyUnexpected: false})
	ctx := context.Background()
	_ = m.recordExternal(ctx, t0, EvidenceUPnP, []External{fwd(22, "192.168.1.60")})
	_ = m.notifyChanges(ctx)
	if len(log.all()) != 0 {
		t.Fatalf("off: %+v", log.all())
	}
}

// Review Focus 1: die Baseline erzeugt keine Meldung, ein neuer Port danach nur mit eingeschaltetem Schalter.
func TestNotifyListenOnlyWhenEnabledAndNotBaseline(t *testing.T) {
	m, log := notifyModule(t, Settings{NotifyListen: true})
	ctx := context.Background()
	_ = m.recordSelf(ctx, t0, []Listen{selfRow("tcp", 8080)})
	_ = m.notifyChanges(ctx)
	if len(log.all()) != 0 {
		t.Fatalf("baseline must stay quiet: %+v", log.all())
	}
	_ = m.recordSelf(ctx, t0.Add(5*time.Minute), []Listen{selfRow("tcp", 8080), selfRow("tcp", 9000)})
	_ = m.notifyChanges(ctx)
	got := log.all()
	if len(got) != 1 || got[0].Kind != notify.KindExposureListen || got[0].Check.Name != "tcp/9000" {
		t.Fatalf("listen alert: %+v", got)
	}
	// Schalter aus: der naechste neue Port wird still verarbeitet
	_ = m.saveRaw(ctx, Settings{IntervalHours: 24, KeepDays: 90, NotifyListen: false})
	_ = m.recordSelf(ctx, t0.Add(10*time.Minute), []Listen{selfRow("tcp", 8080), selfRow("tcp", 9000), selfRow("tcp", 9001)})
	_ = m.notifyChanges(ctx)
	if len(log.all()) != 1 {
		t.Fatal("switched off: no alert")
	}
	_ = m.saveRaw(ctx, Settings{IntervalHours: 24, KeepDays: 90, NotifyListen: true})
	_ = m.notifyChanges(ctx)
	if len(log.all()) != 1 {
		t.Fatal("an event processed while the switch was off is not reported later")
	}
}

// Review Focus 3: viele Aenderungen ergeben eine Meldung mit gekuerztem Betreff.
func TestNotifyBundles(t *testing.T) {
	m, log := notifyModule(t, Settings{NotifyUnexpected: true})
	ctx := context.Background()
	var rows []External
	for i := 0; i < 300; i++ {
		rows = append(rows, fwd(2000+i, "192.168.1.60"))
	}
	_ = m.recordExternal(ctx, t0, EvidenceUPnP, rows)
	_ = m.notifyChanges(ctx)
	got := log.all()
	if len(got) != 1 || got[0].Data["count"] != "300" {
		t.Fatalf("one bundle for 300 forwards: %d alerts", len(got))
	}
	if n := strings.Count(got[0].Check.Name, "tcp/"); n != 5 || !strings.Contains(got[0].Check.Name, "…") {
		t.Fatalf("subject names at most 5 entries and an ellipsis: %q", got[0].Check.Name)
	}
	if strings.Count(got[0].Data["list"], "→") > 10 || !strings.Contains(got[0].Data["list"], "…") {
		t.Fatalf("the list is cut as well: %q", got[0].Data["list"])
	}
}

// Review Focus 1: ein Neustart (neue Instanz, gleiche Datenbank) meldet nichts nach.
func TestNotifyNoRepeatAfterRestart(t *testing.T) {
	m, log := notifyModule(t, Settings{NotifyUnexpected: true})
	ctx := context.Background()
	_ = m.recordExternal(ctx, t0, EvidenceUPnP, []External{fwd(22, "192.168.1.60")})
	_ = m.notifyChanges(ctx)
	second := New(m.core, m.log, "test")
	log2 := &alertLog{}
	second.SetNotifier(log2.add)
	_ = second.notifyChanges(ctx)
	if len(log.all()) != 1 || len(log2.all()) != 0 {
		t.Fatalf("restart: first %d, second %d", len(log.all()), len(log2.all()))
	}
}

// Review Focus 2: eine flatternde Weiterleitung wird hoechstens einmal je 24 Stunden gemeldet.
func TestNotifyFlappingSuppressed(t *testing.T) {
	m, log := notifyModule(t, Settings{NotifyUnexpected: true})
	ctx := context.Background()
	flap := func(at time.Time, present bool) {
		var rows []External
		if present {
			rows = []External{fwd(22, "192.168.1.60")}
		}
		_ = m.recordExternal(ctx, at, EvidenceUPnP, rows)
		_ = m.notifyChanges(ctx)
	}
	flap(t0, true)
	flap(t0.Add(30*time.Minute), false)
	flap(t0.Add(time.Hour), true) // wieder da, 1 Stunde nach der Meldung
	if n := len(log.all()); n != 1 {
		t.Fatalf("within 24 hours only the first is reported, got %d", n)
	}
	flap(t0.Add(2*time.Hour), false)
	flap(t0.Add(25*time.Hour), true) // mehr als 24 Stunden nach der ersten Meldung
	if n := len(log.all()); n != 2 {
		t.Fatalf("after 24 hours it is reported again, got %d", n)
	}
}

func TestNotifyGoneForwardIsSilent(t *testing.T) {
	m, log := notifyModule(t, Settings{NotifyUnexpected: true, NotifyNew: true})
	ctx := context.Background()
	_ = m.recordExternal(ctx, t0, EvidenceUPnP, []External{fwd(22, "192.168.1.60")})
	_ = m.recordExternal(ctx, t0.Add(time.Minute), EvidenceUPnP, nil) // schon wieder weg, bevor gemeldet wird
	if err := m.notifyChanges(ctx); err != nil {
		t.Fatal(err)
	}
	if len(log.all()) != 0 {
		t.Fatalf("a forward that is already gone is not reported: %+v", log.all())
	}
	for _, e := range eventsOf(t, m) {
		if !e.Notified {
			t.Fatalf("every event is processed: %+v", e)
		}
	}
}

func TestNotifyWithoutNotifier(t *testing.T) {
	m := newTestModule(t)
	ctx := context.Background()
	_ = m.recordExternal(ctx, t0, EvidenceUPnP, []External{fwd(22, "192.168.1.60")})
	if err := m.notifyChanges(ctx); err != nil {
		t.Fatalf("no notifier: %v", err)
	}
	for _, e := range eventsOf(t, m) {
		if e.Notified {
			t.Fatalf("without a notifier nothing is marked as processed: %+v", e)
		}
	}
}

func TestNotifyRunAllSendsForwardAlert(t *testing.T) {
	fastScan(t)
	f := newFakeIGD(t, fakeEntry{22, "TCP", 22, "192.168.1.60", "1", "SSH"})
	m, _ := upnpModule(t, f)
	log := &alertLog{}
	m.SetNotifier(log.add)
	if err := m.saveRaw(context.Background(), Settings{IntervalHours: 24, KeepDays: 90, UPnP: true, NotifyUnexpected: true}); err != nil {
		t.Fatal(err)
	}
	if err := m.RunNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := log.all()
	if len(got) != 1 || got[0].Kind != notify.KindExposureUnexpected {
		t.Fatalf("a run reports a new unexpected forward: %+v", got)
	}
}

// Review (final): zwei Meldungen derselben Art im selben Takt tragen verschiedene EventIDs.
func TestNotifyEventIDsAreUnique(t *testing.T) {
	m, log := notifyModule(t, Settings{NotifyUnexpected: true})
	ctx := context.Background()
	_ = m.recordExternal(ctx, t0, EvidenceUPnP, []External{fwd(22, "192.168.1.60")})
	_ = m.notifyChanges(ctx)
	_ = m.recordExternal(ctx, t0, EvidenceUPnP, []External{fwd(22, "192.168.1.60"), fwd(23, "192.168.1.60")})
	_ = m.notifyChanges(ctx) // dasselbe "now" wie die erste Meldung
	got := log.all()
	if len(got) != 2 || got[0].EventID == got[1].EventID {
		t.Fatalf("event ids: %+v", got)
	}
}

// Review (final): die Meldung traegt die Zeit des Versands, nicht die des Taktes (ein Scan kann Minuten dauern).
func TestNotifyAlertTimeIsSendTime(t *testing.T) {
	m, log := notifyModule(t, Settings{NotifyUnexpected: true})
	ctx := context.Background()
	_ = m.recordExternal(ctx, t0, EvidenceUPnP, []External{fwd(22, "192.168.1.60")})
	m.sendChanges(ctx) // t0 liegt lange zurueck
	got := log.all()
	if len(got) != 1 || time.Since(got[0].Time) > time.Minute {
		t.Fatalf("alert time: %+v", got)
	}
}
