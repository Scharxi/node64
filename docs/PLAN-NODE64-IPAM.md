# Node64 – Modul IPAM (Planung)

Stand 2026-11-09. Entwurf, noch nicht abgenommen. Kein Code geschrieben.

Wer es liest, soll daraus einen Umsetzungsplan machen können, ohne nachzufragen. Was als **Annahme** markiert ist,
hat der Verfasser entschieden, nicht Lucas; es ist leicht änderbar.

## Wozu

Heimnetz-Nutzer halten heute gar nicht fest, welche Adresse wem gehört, oder sie nutzen schwere Werkzeuge wie NetBox
oder phpIPAM. Beides passt nicht zu Node64: Was man erst mühsam anlegen muss, bleibt leer.

IPAM in Node64 ist ein **Adressverzeichnis, das sich selbst füllt**. Man legt Subnetze einmal an. Geräte und Namen
kommen aus Quellen, die die Node ohnehin kennt (DNS64, Nachbartabelle, optional ein Scan). Man ergänzt nur, was nur
man selbst weiß: einen Namen, eine Reservierung, eine Notiz.

## Rahmen (entschieden, Lucas 2026-11-09)

- **Umfang:** Dokumentation von Subnetzen, Adressen und Reservierungen, dazu ein **optionaler, einstellbarer Scan**.
- **Eigenständig:** IPAM läuft ohne DNS64. DNS64 ist nur eine **freiwillige Quelle** (Geräte, Namen) und ein
  **freiwilliges Ziel** (Name in DNS eintragen).
- **Seite:** Karten je Subnetz mit Belegungsbalken, darunter die Adressliste mit Status (Entwurf A, abgenommen).
- **Unbekannte Geräte** erscheinen als „neu". Eine Meldung über die Benachrichtigungskanäle gibt es nur, wenn man sie
  einschaltet.
- **Scan:** nur wenn je Subnetz eingeschaltet, Standard aus.
- Modul optional wie alle anderen: ausgeschaltet keine Goroutinen, kein Menüpunkt, kein Verkehr.

## Nicht-Ziele und Anti-Ziele

Nicht-Ziele:
- Kein NetBox-Ersatz: keine Racks, Gerätetypen, VRFs, Kabel, Standorte.
- Kein DHCP-Server und keine Vergabe von Adressen.
- Kein Port-Scan, keine Betriebssystem- oder Dienst-Erkennung.
- Kein Durchscannen von IPv6-/64-Netzen (unmöglich) und kein Scan öffentlicher Netze.
- Kein Abgleich über den Cluster in der ersten Fassung, nichts am Portal (`deploy/web`) und an den hubs.

Anti-Ziele (wäre ein Fehlschlag, auch wenn es technisch läuft):
- **Pflegeaufwand:** wenn man erst viel eintragen muss, bevor die Seite etwas zeigt.
- **Alarmflut:** viele Meldungen über „neue" Geräte, die man nie abstellen kann.
- **Ein Scan, der das Netz stört** oder ohne Wissen des Nutzers läuft.

## Was Node64 schon mitbringt

Einzelheiten stehen im Architektur-Scan dieses Gesprächs; hier nur, was für IPAM zählt.

- **Modulsystem:** `internal/module/module.go` (Lebenszyklus, Migrationen erst beim Einschalten, Seiten über
  `Templater`, Dashboard-Karte über `CardProvider`, `Exporter`, `MetricsProvider`). Vorlage mit eigenen Tabellen:
  `internal/dyndns`.
- **Geräte aus DNS64:** `dns64.Module.NetDevices(ctx)` (Name, IP der letzten 24 Stunden). Healthchecks nutzt das
  schon (`cmd/node64/main.go`, `SetNetDevices`). Fehlt bei Anonymisierung „mask" oder „hide" (dann keine volle
  Adresse im Log).
- **Nachbartabelle:** `groups.Neighbors()` in `internal/dns64/groups` (IP → MAC per Netlink, nur Linux, nur im selben
  Netzsegment bzw. mit `network_mode: host`).
- **Ping:** `internal/checks/icmp.go` mit pro-bing. Im Container nötig: `net.ipv4.ping_group_range=0 65535` oder
  `NET_RAW` (README, Abschnitt ICMP). `internal/caps` schaltet erlaubte Rechte beim Start scharf.
- **Meldungen:** Dispatcher in `internal/notify`, Arten in `senders.go` (Muster: `honeypot_new`, gebündelt, höchstens
  stündlich).
- **Weiteres:** Audit-Bereiche (`internal/web/audit_areas.go`), i18n (`de.json`/`en.json`), OpenAPI
  (`internal/web/static/openapi.json`), MCP-Bereiche (`internal/mcp/mcp.go`), Testscopes
  (`internal/store/storetest/storetest.go`).

## Grundentwurf

### Begriffe

- **Subnetz:** Name, Netz (IPv4 oder IPv6, CIDR), Notiz, Scan an/aus, Scan-Intervall.
- **Adresse:** gehört zu einem Subnetz; Name, MAC, Notiz, Reservierung, zuletzt gesehen, Quelle.
- **Status einer Adresse** (berechnet, nicht gespeichert):
  - *belegt:* in den letzten N Minuten gesehen (Annahme: 2 Scan-Intervalle, ohne Scan 24 Stunden wie bei DNS64).
  - *offline:* früher gesehen, jetzt nicht. Löscht nichts und gibt die Adresse nicht frei.
  - *reserviert:* vom Nutzer gesetzt, unabhängig davon, ob das Gerät da ist.
  - *neu:* gesehen, aber weder benannt noch bestätigt noch ignoriert. Bleibt, bis der Nutzer es abhakt.
  - *frei:* nicht in der Liste (nur in der Belegungszahl).
- **Konflikt (Annahme):** eine Reservierung mit MAC, und es wird dieselbe Adresse mit einer anderen MAC gesehen.
  Zeigt einen Hinweis an der Karte und an der Adresse.

### Quellen

| Quelle | Immer | Liefert | Bedingung |
| --- | --- | --- | --- |
| DNS64 (`NetDevices`) | ja, wenn DNS64 läuft | IP, Name | keine Anonymisierung |
| Nachbartabelle | ja | IP, MAC | Linux, gleiches Segment bzw. Host-Netzwerk |
| Proxmox/Docker aus Healthchecks | später | IP, Name | Schnittstelle erst prüfen (siehe Phase I5) |
| Aktiver Scan | nein, je Subnetz | IP (Antwort), danach MAC aus der Nachbartabelle | Rechte für Ping, siehe unten |
| Handeingabe | ja | alles | – |

Jede Adresse merkt sich die zuletzt liefernde Quelle (Anzeige und Fehlersuche).

### Scan

- Je Subnetz einschaltbar, Standard aus. Seite zeigt vor dem Einschalten, was passiert und was dafür nötig ist.
- ICMP-Echo über pro-bing wie in `internal/checks/icmp.go`. Parallel begrenzt (Annahme: 16), Pause zwischen
  Anfragen einstellbar, Zeitlimit je Adresse 1 Sekunde. Ein /24 braucht damit rund eine Minute.
- Intervall je Subnetz einstellbar (Annahme: Standard stündlich) und ein Knopf „Jetzt scannen".
- **Grenzen (Annahmen):**
  - IPv4 nur bis /22 (1022 Adressen); größere Netze lehnt die Oberfläche ab.
  - Nur private Bereiche: 10/8, 172.16/12, 192.168/16, 100.64/10 (CGNAT) und ULA `fc00::/7`. Öffentliche Netze und
    Link-Local lehnt das Modul beim Anlegen des Scans ab.
  - IPv6: kein Durchsuchen. Nur Adressen, die aus anderen Quellen bekannt sind, werden erneut angepingt.
- Nach einem Treffer wird die MAC aus der Nachbartabelle geholt. Ohne Host-Netzwerk bleibt die MAC leer, der Treffer
  zählt trotzdem.
- Fehlen die Rechte, zeigt die Seite den Grund und den Weg (README-Hinweis zu `ping_group_range`/`NET_RAW`), statt
  still nichts zu tun.
- Der Scan sieht nur Subnetze, die der Container erreicht. In einer Docker-Bridge ist das meist nur das Bridge-Netz;
  für das Heimnetz braucht es `network_mode: host`. Die Seite sagt das deutlich.

### Meldungen

- Neue Arten in `internal/notify/senders.go` (Annahme): `ipam_new` (neue unbekannte Geräte, gebündelt, höchstens
  stündlich) und `ipam_conflict`. Standard **aus**, einschaltbar im Modul.
- Ruhezeit und Kanäle wie bei den anderen Modulen.

### Dashboard und weitere Anbindungen

- Dashboard-Karte (`CardProvider`): Zahl der Subnetze, belegte Adressen, neue Geräte, Konflikte.
- Prometheus (`MetricsProvider`): `node64_ipam_subnet_used`, `node64_ipam_subnet_size`, `node64_ipam_new_devices`.
- Export/Import (`Exporter`): Subnetze, Namen, Notizen, Reservierungen. Nicht: „zuletzt gesehen" und Scan-Zustand.
- Lokale API `/api/ipam/*` mit Eintrag in `openapi.json`.
- **Ziel DNS64:** Knopf „In DNS64 eintragen" an einer Adresse mit Name (nur wenn DNS64 läuft), nach dem Muster des
  Knopfs „lokal in DNS64 eintragen" in der DNS64-Host-Liste.
- **Healthchecks:** Knopf „Als Check" an einer Adresse (nur wenn Healthchecks läuft), Muster wie bei DNS64-Geräten.
- **MCP:** späterer Bereich `ipam`, nur lesend.

### Cluster und Datenschutz

- **Cluster:** in der ersten Fassung **nur lokal** (Subnetze gehören zum Standort). Ein Abgleich wäre später ein
  eigener Bereich, Standard aus, nach `docs/PLAN-NODE64-CLUSTER-MODULE.md`.
- **Datenschutz:** Die Liste enthält MAC-Adressen und Gerätenamen. Sie bleibt auf der Node, geht nie an Portal oder
  hubs und taucht nicht in Logs auf. Mit DNS64-Anonymisierung („mask"/„hide") liefert DNS64 keine Geräteadressen;
  IPAM zeigt dann nur Scan- und Nachbardaten. Vor Auslieferung gegen `docs/DATENSCHUTZ-NEUE-DIENSTE.md` prüfen.

## Datenmodell (Vorschlag)

Migrationsbereich `ipam`, Tabellen mit Präfix `ipam_`:

- `ipam_subnets`: `id`, `name`, `cidr` (eindeutig), `family`, `note`, `scan_enabled`, `scan_interval_min`,
  `last_scan_at`, `last_scan_error`, `created_at`, `updated_at`.
- `ipam_addresses`: `id`, `subnet_id`, `ip`, `name` (von Hand), `source_name` (Name aus einer Quelle), `mac`, `note`,
  `reserved`, `acknowledged`, `ignored`, `first_seen`, `last_seen`, `last_source`, `created_at`; eindeutig über
  (`subnet_id`, `ip`).
- Einstellungen in `settings`: `ipam.scan_parallel`, `ipam.scan_delay_ms`, `ipam.notify_new`, `ipam.notify_conflict`.

Adressen, die nur gesehen wurden und nie benannt, bestätigt oder reserviert, werden nach einer einstellbaren Frist
gelöscht (Annahme: 90 Tage ohne Sichtung), damit die Tabelle in einem wechselnden Gäste-WLAN nicht wächst.

## Phasen (Vorschlag)

| Phase | Inhalt | Ergebnis |
| --- | --- | --- |
| I1 | Gerüst: Paket `internal/ipam`, Registrierung in `main.go`, Migration, Subnetze anlegen und löschen, Seite mit Karten, i18n de/en, Audit-Bereich, Testscope, Changelogs, Version 0.1.0 | Modul einschaltbar, Karten ohne Daten |
| I2 | Adressen: Liste, Quellen DNS64 und Nachbartabelle, Status, Name/Notiz/Reservierung, „neu" abhaken, Konflikt, lokale API und OpenAPI | Seite füllt sich selbst |
| I3 | Aktiver Scan: je Subnetz, Intervall, „Jetzt scannen", Grenzen, Hinweis bei fehlenden Rechten | Scan optional nutzbar |
| I4 | Meldungen (`ipam_new`, `ipam_conflict`), Dashboard-Karte, Prometheus, Export/Import | Beobachtbar und sicherbar |
| I5 | Anbindungen: „In DNS64 eintragen", „Als Check", Proxmox/Docker als Quelle (Schnittstelle erst prüfen), MCP | Zusammenspiel mit anderen Modulen |

Reihenfolge je Phase wie im Projekt üblich: Test zuerst, Tests auf der Box (`ssh agentbox`), `gofmt` sauber,
`node --check` für JS, Modulversion und beide Changelogs im selben Commit.

## Annahmen des Verfassers (bitte prüfen)

1. Menüreihenfolge und Symbol (Symbol z. B. `bi-diagram-3`; Order beim Bau gegen die vorhandenen Module prüfen).
2. Status „belegt" nach 2 Scan-Intervallen bzw. 24 Stunden ohne Scan.
3. Scan-Voreinstellungen: stündlich, 16 parallel, bis /22, nur private Bereiche.
4. Konflikt-Erkennung über die MAC einer Reservierung.
5. Aufräumfrist 90 Tage (IPv4) bzw. 7 Tage (IPv6) für nur gesehene Adressen.
6. Export ohne „zuletzt gesehen" und Scan-Zustand.
7. `groups.Neighbors()` direkt aus `internal/dns64/groups` nutzen, statt es in ein eigenes Paket zu verschieben
   (kein Umbau ohne Auftrag). Das Paket ist ein kleines Blatt ohne Abhängigkeit zum Modul DNS64.

## Festlegungen aus der Prüfung (Annahmen des Verfassers)

Ein unabhängiger Leser des Entwurfs hat nachgefragt; diese Punkte sind entschieden, aber noch von Lucas zu prüfen.

**Wann gilt „gesehen"?**
- Ohne Scan fragt IPAM DNS64 und die Nachbartabelle alle 60 Sekunden ab. `last_seen` ist der Zeitpunkt der Abfrage,
  bei DNS64 besser die echte Zeit der letzten Anfrage des Geräts.
- Dafür wird `dns64.NetDevice` **additiv** um `MAC` und `LastSeen` erweitert (bestehende Aufrufer, z. B. Healthchecks,
  bleiben unverändert; keine DNS64-Versionserhöhung, die Änderung ist nicht nutzersichtbar, siehe `CLAUDE.md`). Das ist die einzige Änderung an einem anderen
  Modul. Ohne diese Erweiterung greift die Konflikt-Erkennung bei DNS64-Treffern nicht.
- DNS64 liefert höchstens 200 Clients der letzten 24 Stunden (`RecentClients`). Das ist eine bekannte Grenze der
  Quelle und wird in der Oberfläche vermerkt, nicht umgangen.
- Nachbareinträge im Zustand STALE gelten nicht als Beweis der Anwesenheit; der Parser reicht den Zustand dafür mit.

**IPv6 und wechselnde MACs**
- Link-Local (`fe80::/10`) wird nie aufgenommen.
- Die Adresse bleibt die Einheit (kein eigenes „Gerät"). Eine neue IPv6-Adresse, deren MAC im selben Subnetz schon
  einer bekannten Adresse gehört, gilt nicht als „neu" und löst keine Meldung aus.
- Nur gesehene, nie benannte IPv6-Adressen werden nach 7 Tagen ohne Sichtung gelöscht (rotierende Privacy-Adressen),
  IPv4 nach 90 Tagen.
- Zufällige MACs (iOS/Android „private Adresse") können Konflikte vortäuschen. Die Konflikt-Erkennung gilt deshalb nur
  für Adressen mit **von Hand gesetzter** MAC-Reservierung; die Hilfe nennt das Problem.

**Was ist „neu"?**
- Ein Name aus einer Quelle (DNS64, später Proxmox/Docker) macht ein Gerät **nicht** neu; die Node kennt es ja.
- Beim ersten Lauf eines Subnetzes gelten alle gefundenen Geräte als „neu", aber es gibt **keine Meldung** und einen
  Knopf „Alle bestätigen". So ist die Seite beim ersten Öffnen nicht überladen und trotzdem ehrlich.
- „Ignoriert" und „bestätigt" bleiben erhalten und werden nicht von der Aufräumfrist erfasst.

**Rangfolge und Zuordnung**
- Der Name von Hand schlägt den Namen aus Quellen (`name` vor `source_name`); Quellen überschreiben nie Handeingaben.
- Gesehene Adressen außerhalb aller angelegten Subnetze werden nicht gespeichert. Die Seite zeigt einen Hinweis
  „N Adressen außerhalb deiner Subnetze" mit Knopf zum Anlegen eines Subnetzes.
- Überlappende Subnetze werden beim Anlegen abgelehnt.
- Löschen eines Subnetzes löscht seine Adressen, nach Bestätigung.

**Scan im Docker-Bridge-Modus**
- Der Scan ist trotzdem erlaubt. Liegt das Subnetz nicht an einem Interface des Containers, zeigt die Seite: „Über
  ein Gateway erreichbar, MAC-Adressen unbekannt." Erkennung über `net.Interfaces()`.

**Reservierungen**
- Eine Reservierung ohne Gerät bleibt „reserviert", zählt in der Belegung als reserviert und nicht als belegt.

## Dem Builder überlassen

- Genaue Spalten und Filter der Adressliste.
- Gestaltung der Formulare, Texte und der Hinweise bei fehlenden Rechten.
- Herstellererkennung aus der MAC (Idee, nicht Teil von I1 bis I4).
- Aufbau der Tests im Einzelnen.
