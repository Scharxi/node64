package notify

import (
	"strings"
	"testing"
	"time"
)

// Exposure-Check: drei Arten, alle Modul-Meldungen ohne Check; nur "unerwartet" gilt als Stoerung.
func TestExposureKinds(t *testing.T) {
	for _, k := range []Kind{KindExposureUnexpected, KindExposureNew, KindExposureListen} {
		if !IsExposure(k) || !IsModule(k) {
			t.Fatalf("%s must be an exposure module message", k)
		}
	}
	if IsExposure(KindHoneypotNew) || IsExposure(KindDown) {
		t.Fatal("other kinds are not exposure messages")
	}
	if !isDownKind(KindExposureUnexpected) || isDownKind(KindExposureNew) || isDownKind(KindExposureListen) {
		t.Fatal("only unexpected counts as a problem")
	}
	if st := haState(Message{Kind: KindExposureUnexpected}); st != "down" {
		t.Fatalf("unexpected state %q", st)
	}
	for _, k := range []Kind{KindExposureNew, KindExposureListen} {
		if st := haState(Message{Kind: k}); st != "info" {
			t.Fatalf("%s state %q", k, st)
		}
	}
	if color, _ := mailStatus(KindExposureUnexpected, "de"); color != "#d63939" {
		t.Fatalf("unexpected must be red, got %s", color)
	}
	if color, _ := mailStatus(KindExposureNew, "de"); color == "#d63939" {
		t.Fatal("a new expected forward is no alarm")
	}
}

func TestExposureAlerts(t *testing.T) {
	d, st, rec := testDispatcher(t, nil)
	addChannel(t, st, "default", true)
	info := CheckInfo{Name: "tcp/22, tcp/443", NotifyDown: true, NotifyUp: true, Local: true}
	data := map[string]string{"text": "notify.text.exposure_unexpected", "count": "2", "list": "tcp/22 → 192.168.1.60:22, tcp/443 → 192.168.1.61:443"}
	d.Dispatch(Alert{EventID: "e1", Kind: KindExposureUnexpected, Check: info, Time: time.Now(), Data: data})
	d.Dispatch(Alert{EventID: "e2", Kind: KindExposureNew, Check: CheckInfo{Name: "tcp/8443", NotifyDown: true, NotifyUp: true, Local: true}, Time: time.Now(),
		Data: map[string]string{"text": "notify.text.exposure_new", "count": "1", "list": "tcp/8443 → 192.168.1.5:8443"}})
	msgs := waitMsgs(t, rec, 2)
	byKind := map[Kind]Message{}
	for _, m := range msgs {
		byKind[m.Kind] = m
	}
	u, n := byKind[KindExposureUnexpected], byKind[KindExposureNew]
	if u.Priority != 4 || n.Priority != 2 {
		t.Fatalf("priorities: unexpected %d, new %d", u.Priority, n.Priority)
	}
	if !strings.Contains(u.Title, "tcp/22, tcp/443") || !strings.Contains(u.Text, "192.168.1.60:22") || (u.URL != "" && !strings.HasSuffix(u.URL, "/exposure")) {
		t.Fatalf("unexpected message: %+v", u)
	}
}
