# Node64 – Modul Exposure-Check (Planung)

Stand 2026-11-09, überarbeitet (zwei Spuren). Phase E1 (Spur 1) ist umgesetzt (Modul `exposure` 0.1.0, Umsetzungsplan `docs/superpowers/plans/2026-11-09-exposure-e1.md`); E2 (UPnP-Indiz, Zusammenführung, Einordnung; Umsetzungsplan `docs/superpowers/plans/2026-11-09-exposure-e2.md`) ist umgesetzt (0.2.0); E3 bis E6 stehen noch aus.
Issue: Scharxi/node64 #23.

Was als **Annahme** markiert ist, hat der Verfasser entschieden, nicht Lucas; es ist leicht änderbar.

## Wozu

Zwei Fragen, die zusammengehören und getrennt beantwortet werden:

1. **Spur 1 – „Lauscht“:** *Auf welcher IP-Adresse sind welche Ports offen, bzw. wird dort gehört?* (Innen-Sicht)
2. **Spur 2 – „Erreichbar“:** *Welche Ports sind aus dem Internet erreichbar?* (Außen-Sicht)

Der Nutzen liegt im Vergleich: Ein Port, der lauscht **und** erreichbar ist, ist die Angriffsfläche. Ein Port, der nur
lauscht, ist es nicht. Die Seite zeigt beide Spuren nebeneinander und sagt dazu ehrlich, **wie sicher** jede Aussage ist.

## Rahmen (Annahmen des Verfassers)

- **Zwei getrennte Spuren mit eigener Zuverlässigkeit.** Spur 1 ist von innen verlässlich. Spur 2 ist von innen
  **nicht** verlässlich messbar (NAT-Loopback, bei IPv6 läuft Verkehr im selben Netz nicht über die Router-Firewall);
  sie braucht einen Messpunkt außerhalb oder bleibt ein Indiz.
- **Vertrauensstufen in Spur 2**, nie ein einzelner Haken „sicher“:
  - **bestätigt:** ein Messpunkt außerhalb hat den Port offen gefunden.
  - **wahrscheinlich:** der Router meldet eine Weiterleitung (UPnP) und das Ziel lauscht dort, ohne Bestätigung.
  - **unbekannt:** weder Bestätigung noch Indiz (z. B. IPv6-Firewall von innen nicht sichtbar).
- **Nur eigene Netze.** Spur 1 prüft nur private Bereiche der angelegten IPAM-Subnetze, Spur 2 nur die eigene
  öffentliche Adresse (Absenderadresse der Anfrage, bei IPv6 auch Adressen im selben /64), nie ein frei wählbares Ziel.
  Das ist der Missbrauchsschutz: ohne ihn wäre der Dienst ein Portscanner.
- **TCP zuerst.** UDP lässt sich weder von innen noch von außen zuverlässig prüfen.
- **Läuft auch ohne ipv64.** Außen-Messpunkte sind austauschbar; ipv64 ist nur eine Option.
- Modul optional wie alle: ausgeschaltet kein Verkehr, keine Goroutinen, kein Menüpunkt. Standard **aus**. Scans
  einzeln einschaltbar.

## Nicht-Ziele und Anti-Ziele

Nicht-Ziele:
- Kein allgemeiner Portscanner, keine Prüfung fremder Adressen, keine Dienst- oder Versionserkennung, keine Schwachstellensuche.
- Kein Durchsuchen ganzer IPv6-Präfixe (unmöglich); nur bekannte Adressen.

Anti-Ziele:
- **Falsche Sicherheit:** „keine erreichbaren Ports“ heißt nur „keiner der geprüften Ports bestätigt“. Die Seite sagt das.
- **Abhängigkeit von ipv64:** ein Nutzer ohne Account bekommt trotzdem Spur 1 und Indizien in Spur 2.
- **Alarmflut:** Meldungen nur bei Änderungen und bei Unerwartetem.
- **Störung im Netz:** Scans bremsen sich (Parallelität, Pausen) und laufen nie ungefragt.

## Was schon da ist

- **Die Node selbst:** `internal/netstat.Listeners()` liest `/proc/net/tcp` und `/proc/net/udp` (Linux) und liefert die
  lauschenden Sockets **ohne jeden Netzverkehr**. Im Container gilt der Netz-Namensraum des Containers, mit
  `network_mode: host` der des Hosts. Die Port-Verwaltung (`internal/ports`) kennt zusätzlich, welches Modul welchen Port belegt.
- **Geräte im LAN:** IPAM (Subnetze, Adressen, Namen); der geplante Scan aus Issue #2 liefert dieselbe Grundlage
  (private Bereiche, Begrenzung, Rechte).
- **Öffentliche Adresse und CGNAT-Erkennung:** `internal/dyndns/detect.go` (Anschluss-Analyse). Bei CGNAT/DS-Lite
  entfällt die IPv4-Prüfung in Spur 2.
- **Cluster ohne ipv64:** Nodes sprechen per signierten `/peer/*`-Aufrufen, der Account darf „0“ sein
  (`docs/CLUSTER.md`). Einschränkung: beide Seiten müssen sich erreichen; als Messpunkt nicht ausreichend (siehe Spur 2).
- **Meldungen, Dashboard-Karte, Metriken, Export:** Dispatcher in `internal/notify`, `module`-Schnittstellen.
- **ipv64-Aufrufe:** zentraler API-Key (`internal/ipv64api`), Muster Honeypot-Frühwarnung (`internal/honeypot/watch.go`).

## Spur 1 – „Lauscht“ (Innen-Sicht)

**Frage:** Auf welcher Adresse sind welche Ports offen?

| Ziel | Wie | Zuverlässigkeit |
| --- | --- | --- |
| **Die Node selbst** | `netstat.Listeners()` (kein Verkehr), je Port das belegende Modul aus der Port-Verwaltung | hoch (exakt), nur im eigenen Namensraum |
| **Geräte im LAN** | TCP-Connect auf eine Portliste je Adresse der IPAM-Subnetze | hoch für die geprüften Ports; nicht geprüfte Ports bleiben unbekannt |

- LAN-Scan: **opt-in je Subnetz**, nur private Bereiche (wie IPAM-Scan), begrenzt parallel, Pause zwischen Anfragen,
  Zeitlimit je Verbindung. Er teilt sich Schutzregeln und Rechte mit dem IPAM-Scan (Issue #2); bis dahin ein eigener
  kleiner Scanner (Entscheidung des Builders).
- Portliste: rund 100 häufige Ports plus die Ports der Port-Verwaltung und eigene des Nutzers.
- Ergebnis je Adresse: Port, Zustand (offen/zu), Dienstname (bei der Node: das Modul), zuerst und zuletzt gesehen.
  Namen kommen aus IPAM.
- Bindung: bei der Node unterscheidet die Anzeige „lauscht auf allen Adressen“ (`0.0.0.0`/`::`) von „nur lokal“
  (`127.0.0.1`).

## Spur 2 – „Erreichbar“ (Außen-Sicht)

**Frage:** Welche Ports sind aus dem Internet erreichbar? Drei Quellen, die unterschiedlich sicher sind:

### Indiz: Router fragen (UPnP IGD) — ohne Server

Die Node liest vom Router die **aktiven Weiterleitungen** (`GetGenericPortMappingEntry`) und die externe Adresse
(`GetExternalIPAddress`). Das ist die Stufe **wahrscheinlich**, wenn das Ziel dort lauscht (Spur 1 passt dazu).

- Vorteil: zeigt je Weiterleitung die interne Adresse („das NAS hat Port 5000 geöffnet“), IPAM macht daraus einen Namen.
- Grenzen: nur wenn der Router UPnP anbietet und die Liste herausgibt; feste Weiterleitungen des Nutzers fehlen oft;
  SSDP braucht Host-Netzwerk (die Beschreibungs-URL lässt sich auch von Hand eintragen). NAT-PMP/PCP können nicht auflisten.
- Technik (Annahme): SSDP, Gerätebeschreibung, SOAP, alles mit der Standardbibliothek.

### Bestätigung 1: Messpunkt „eigene Node an einem anderen Ort“

Eine zweite Node (VPS, Bekannte, Büro) verbindet sich von außen mit der öffentlichen Adresse. **Aktuell nicht
verfügbar** (keine zweite Node vorhanden), daher später. Nicht über die Cluster-Mitgliedschaft (die verlangt, dass sich
beide Seiten erreichen), sondern über eine schlanke Messpunkt-Rolle `POST /peer/v1/probe`, die nur ausgehende
Verbindungen der geprüften Node braucht. Pairing und Signatur aus `internal/peer`.

### Bestätigung 2: Messpunkt „ipv64-Server“ (optional, nur verknüpft)

Die hubs (Nürnberg, Falkenstein) können denselben Probe-Vertrag bedienen. Braucht Arbeit und Abnahme beim Betreiber
und kommt zuletzt.

### Probe-Vertrag (für beide Messpunkte gleich)

`POST …/probe`, signiert bzw. mit Key angemeldet.

- Body: `{"ports":[{"proto":"tcp","port":22}, ...], "extra":["2001:db8::1234"]}` (`extra` nur IPv6, nur im /64 der Absenderadresse).
- Antwort: `{"target":"203.0.113.7","results":[{"address":"…","port":22,"proto":"tcp","state":"open|closed|filtered","ms":12}]}`;
  bei längeren Läufen `202` mit Abholung.
- **Regeln für jeden Messpunkt:** nie ein Ziel prüfen, das nicht die Absenderadresse ist (oder im /64 liegt); keine
  privaten, Loopback-, Link-Local- und reservierten Adressen; Zeitlimit je Verbindung; höchstens 100 Ports je Lauf;
  Begrenzung je Zieladresse (Annahme: ein Lauf je 6 Stunden); Ergebnisse nur kurz aufbewahren.
- Fehler: `401/403`, `409` (Absenderadresse nicht öffentlich), `422`, `429`.

## Zusammenführung der Spuren (Seite)

Zwei Tabellen auf einer Seite, dazu eine gemeinsame Sicht:

| Port | Gerät (IPAM) | Lauscht | Erreichbar | Einordnung |
| --- | --- | --- | --- | --- |
| 443 | node64 | ja (alle Adressen) | **bestätigt** | erwartet (Port-Verwaltung) |
| 5000 | NAS | ja | **wahrscheinlich** (UPnP) | **unerwartet** |
| 22 | Drucker | ja | unbekannt | nur im LAN |

- **erwartet:** die Port-Verwaltung belegt ihn oder der Nutzer hat ihn eingetragen. **unerwartet:** erreichbar oder
  wahrscheinlich erreichbar, aber nicht erwartet. **neu / weg:** Änderung gegenüber dem letzten Lauf.
- Bei IPv6 steht „unbekannt“, solange kein Außen-Messpunkt bestätigt hat; die Seite erklärt warum.
- Hinweis auf der Seite: „geschlossen“ und „nicht bestätigt“ beweisen keine Sicherheit.
- Bei CGNAT/DS-Lite statt der IPv4-Außen-Spalte der Hinweis, warum nicht geprüft wird.

## Datenmodell der Node (Vorschlag)

Migrationsbereich `exposure`, Tabellen `exposure_*`:

- `exposure_listen`: `address`, `proto`, `port`, `state`, `service`, `bind` (alle/lokal), `first_seen`, `last_seen`, `source` (self/scan).
- `exposure_external`: `address`, `proto`, `port`, `evidence` (probe/upnp), `prober_id`, `state`, `internal_addr`, `first_seen`, `last_seen`.
- `exposure_probers`: `id`, `kind` (upnp/node/ipv64), `name`, `endpoint`, `secret` (verschlüsselt), `enabled`.
- `exposure_expected`: `proto`, `port`, `address` (leer = alle), `note`.
- Einstellungen in `settings`: `exposure.interval`, `exposure.ports`, `exposure.scan_subnets` (je Subnetz aus IPAM),
  `exposure.notify_new`, `exposure.notify_unexpected`, `exposure.keep_days` (Standard 90).

## Meldungen

Neue Arten (Annahme): `exposure_new` (neuer erreichbarer/wahrscheinlicher Port) und `exposure_unexpected`
(erreichbar ohne Erwartung), gebündelt je Lauf. Standard **an** für „unerwartet“, **aus** für „neu und erwartet“.
Reine „lauscht“-Änderungen im LAN melden nur auf Wunsch.

## Datenschutz und Missbrauch

- Spur 1 bleibt im LAN. Die Ergebnisse (Geräte, offene Ports) liegen nur auf der Node und gehen nirgends hin.
- Zu Außen-Messpunkten gehen nur ein Geheimnis oder Key, die Absenderadresse und die Portliste.
- LAN-Scan: Hinweistext vor dem Einschalten, nur private Bereiche, nur angelegte Subnetze.
- Vor Auslieferung gegen `docs/DATENSCHUTZ-NEUE-DIENSTE.md` prüfen.

## Phasen (Vorschlag)

| Phase | Inhalt | Ergebnis |
| --- | --- | --- |
| E1 | **Spur 1:** die Node selbst (`/proc`) und LAN-Scan je IPAM-Subnetz, Datenmodell, Seite, lokale API, i18n | „Folgende Ports sind auf dieser IP offen“, ohne Server |
| E2 | **Spur 2 Indiz:** UPnP-Abfrage, Zusammenführung, Einordnung (erwartet/unerwartet/neu/weg), Stufen wahrscheinlich/unbekannt | „Wahrscheinlich aus dem Internet erreichbar“ |
| E3 | Meldungen, Dashboard-Karte, Metriken, Export, Verlauf | Beobachtbar im Alltag |
| E4 | **Spur 2 bestätigt:** Messpunkt-Rolle für eine zweite Node (Probe-Endpunkt, Pairing, Missbrauchsschutz) | Stufe „bestätigt“ ohne ipv64 |
| E5 | Messpunkt ipv64-Server (Abnahme durch den Betreiber, zwei Standorte) | Bequem für verknüpfte Nutzer |
| E6 | IPv6-Adressen im /64 aus IPAM, UDP-Sonderfälle | Vollständigeres Bild |

Reihenfolge je Phase wie im Projekt üblich: Test zuerst, Tests auf der Box, `gofmt`, Modulversion und beide
Changelogs im selben Commit. **E1 bis E3 brauchen keine zweite Node und keine Zusage des Betreibers.**

## Offene Punkte

Für Lucas:
1. Reicht es dir, dass „aus dem Internet erreichbar“ zunächst nur als **wahrscheinlich** (UPnP) angezeigt wird, bis es
   einen Außen-Messpunkt gibt?
2. Soll der LAN-Scan ein eigenes Schalter-Set haben oder sich vollständig an den IPAM-Scan hängen (#2)?

Für den Builder:
- Ob `netstat.Listeners()` für die Node genügt oder zusätzlich der belegende Prozess angezeigt werden soll (im
  Container ohne Host-PID-Namensraum meist nicht möglich).
- UPnP-Verhalten verschiedener Router (Liste nicht verfügbar, Authentifizierung).
- Eigene Adressermittlung ohne ipv64 für die CGNAT-Erkennung.
- Ob sich das Pairing der Messpunkt-Rolle an `internal/peer` anlehnen lässt oder getrennt bleibt.

Offene Fragen nur für ipv64 (Betreiber, erst E5): hub-Checker oder PHP-Portal? Zulässige Last je Account und Tag? Für
alle Accounts oder nur bestimmte? Ergebnis je Standort einzeln? Obergrenze und Sperrliste für eigene Ports?

## Dem Builder überlassen

- Gestaltung der Seite und der Texte, Dienstnamen zu Ports.
- Aufbau der Tests im Einzelnen und der Fakes (Router, Messpunkt, Scan-Ziel).
- Genaue Tabellenspalten und Indizes.
