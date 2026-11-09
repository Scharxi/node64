package exposure

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func exportJSON(t *testing.T, m *Module) []byte {
	t.Helper()
	v, err := m.Export(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func seeded(t *testing.T) *Module {
	t.Helper()
	m := newTestModule(t)
	ctx := context.Background()
	fakeIPAM(m, twoSubnets(), nil)
	s := Settings{IntervalHours: 6, Ports: []int{8080, 9000}, UPnP: true, UPnPURL: "http://192.168.1.1:5000/desc.xml", KeepDays: 365, NotifyUnexpected: false, NotifyNew: true, NotifyListen: true, Subnets: []int64{1}}
	if err := m.SaveSettings(ctx, s); err != nil {
		t.Fatal(err)
	}
	_ = m.AddExpected(ctx, "tcp", 443, "Web")
	_ = m.AddExpected(ctx, "udp", 51820, "WireGuard")
	return m
}

func TestExportRoundTrip(t *testing.T) {
	src := seeded(t)
	dst := newTestModule(t)
	ctx := context.Background()
	fakeIPAM(dst, twoSubnets(), nil)
	if err := dst.SaveSettings(ctx, Settings{IntervalHours: 24, KeepDays: 90, NotifyUnexpected: true, Subnets: []int64{2}}); err != nil {
		t.Fatal(err)
	}
	n, err := dst.Import(ctx, exportJSON(t, src))
	if err != nil || n != 3 {
		t.Fatalf("import: %d %v", n, err)
	}
	want, got := src.LoadSettings(ctx), dst.LoadSettings(ctx)
	want.Subnets = []int64{2} // die Subnetz-Auswahl bleibt, wie sie im Ziel war
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("settings:\n want %+v\n  got %+v", want, got)
	}
	exp, _ := dst.Expecteds(ctx)
	if len(exp) != 2 || exp[0].Port != 443 || exp[0].Note != "Web" || exp[1].Proto != "udp" || exp[1].Port != 51820 {
		t.Fatalf("expected: %+v", exp)
	}
}

func TestExportDoesNotLeakSubnets(t *testing.T) {
	b := exportJSON(t, seeded(t))
	if strings.Contains(string(b), "subnet") {
		t.Fatalf("export names subnets: %s", b)
	}
}

func TestImportCountsEntries(t *testing.T) {
	m := newTestModule(t)
	n, err := m.Import(context.Background(), []byte(`{"settings":{"interval_hours":6},"expected":[{"proto":"tcp","port":22,"note":""},{"proto":"udp","port":53}]}`))
	if err != nil || n != 3 {
		t.Fatalf("counts: %d %v", n, err)
	}
	if n, err := m.Import(context.Background(), []byte(`{"unknown":1}`)); err != nil || n != 0 {
		t.Fatalf("unknown fields are ignored: %d %v", n, err)
	}
}

func TestImportPartialGroups(t *testing.T) {
	m := seeded(t)
	ctx := context.Background()
	before := m.LoadSettings(ctx)
	if _, err := m.Import(ctx, []byte(`{"expected":[{"proto":"tcp","port":8443}]}`)); err != nil {
		t.Fatal(err)
	}
	if after := m.LoadSettings(ctx); !reflect.DeepEqual(before, after) {
		t.Fatalf("only expected given: settings stay\n %+v\n %+v", before, after)
	}
	expBefore, _ := m.Expecteds(ctx)
	if _, err := m.Import(ctx, []byte(`{"settings":{"keep_days":30}}`)); err != nil {
		t.Fatal(err)
	}
	if expAfter, _ := m.Expecteds(ctx); !reflect.DeepEqual(expBefore, expAfter) {
		t.Fatalf("only settings given: expected ports stay")
	}
	if s := m.LoadSettings(ctx); s.KeepDays != 30 || s.IntervalHours != 6 || !s.NotifyNew {
		t.Fatalf("fields that are absent keep their value: %+v", s)
	}
}

// Review Focus 4: eine fehlerhafte Datei aendert nichts.
func TestImportRejectsAndChangesNothing(t *testing.T) {
	manyPorts := make([]string, 101)
	for i := range manyPorts {
		manyPorts[i] = strconv.Itoa(20000 + i)
	}
	manyExpected := make([]string, 1001)
	for i := range manyExpected {
		manyExpected[i] = `{"proto":"tcp","port":` + strconv.Itoa(1+i%60000) + `}`
	}
	cases := map[string]string{
		"port 0":          `{"expected":[{"proto":"tcp","port":22},{"proto":"tcp","port":0}]}`,
		"port 65536":      `{"expected":[{"proto":"tcp","port":65536}]}`,
		"101 own ports":   `{"settings":{"ports":[` + strings.Join(manyPorts, ",") + `]},"expected":[{"proto":"tcp","port":22}]}`,
		"public upnp url": `{"settings":{"upnp_url":"http://8.8.8.8/x"},"expected":[{"proto":"tcp","port":22}]}`,
		"interval 7":      `{"settings":{"interval_hours":7},"expected":[{"proto":"tcp","port":22}]}`,
		"keep_days 5":     `{"settings":{"keep_days":5},"expected":[{"proto":"tcp","port":22}]}`,
		"1001 expected":   `{"expected":[` + strings.Join(manyExpected, ",") + `]}`,
		"type error":      `{"settings":{"interval_hours":6},"expected":[{"proto":"tcp","port":"abc"}]}`,
		"bad proto":       `{"expected":[{"proto":"icmp","port":22}]}`,
		"broken json":     `{"settings":`,
	}
	for name, body := range cases {
		m := seeded(t)
		ctx := context.Background()
		settings, expected := m.LoadSettings(ctx), mustExpected(t, m)
		if n, err := m.Import(ctx, []byte(body)); err == nil || n != 0 {
			t.Fatalf("%s: want an error, got %d %v", name, n, err)
		}
		if got := m.LoadSettings(ctx); !reflect.DeepEqual(settings, got) {
			t.Fatalf("%s: settings changed\n %+v\n %+v", name, settings, got)
		}
		if got := mustExpected(t, m); !reflect.DeepEqual(expected, got) {
			t.Fatalf("%s: expected ports changed: %+v", name, got)
		}
	}
}

func mustExpected(t *testing.T, m *Module) []Expected {
	t.Helper()
	e, err := m.Expecteds(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func twoSubnets() []SubnetRef {
	return []SubnetRef{{ID: 1, Name: "Heim", CIDR: netip.MustParsePrefix("192.168.1.0/24")}, {ID: 2, Name: "Gaeste", CIDR: netip.MustParsePrefix("192.168.2.0/24")}}
}
