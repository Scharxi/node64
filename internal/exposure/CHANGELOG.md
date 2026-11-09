# Änderungen – Exposure-Check

## 0.3.0 – 2026-11-09

Im Alltag beobachtbar: Verlauf, Meldungen, Dashboard-Karte, Metriken, Export.

### Neu
- Verlauf: neue und weggefallene Weiterleitungen des Routers und neue oder weggefallene lauschende Ports, neueste zuerst. Die erste Aufnahme einer Adresse erzeugt keine Einträge. Aufbewahrung 30, 90 (Standard), 365 Tage oder unbegrenzt.
- Meldungen über die eingerichteten Kanäle: bei einer neuen *unerwarteten* Weiterleitung (Standard an), optional bei einer neuen *erwarteten* Weiterleitung und bei einem neuen lauschenden Port. Mehrere Änderungen eines Laufs kommen als eine Meldung; dieselbe Änderung wird höchstens einmal in 24 Stunden gemeldet, ein Neustart meldet nichts nach.
- Karte im Dashboard und Kennzahlen unter `/api/metrics` (`node64_exposure_*`); beides liest nur die Datenbank.
- Export und Import der Konfiguration (Einstellungen und erwartete Ports; die Subnetz-Auswahl gehört nicht dazu). Der Import prüft zuerst alles und ändert bei einem Fehler nichts.
- Lokale API: `GET /api/exposure/history`; die Einstellungen kennen `keep_days`, `notify_unexpected`, `notify_new` und `notify_listen`.
- Darstellung: hervorgehobene Zeilen sind im Dunkelmodus lesbar, ein Ziel ohne Namen zeigt die Adresse nur einmal, die Tabellen tragen auf schmalen Schirmen ihre Spaltenbeschriftung.

## 0.2.0 – 2026-11-09

Außen-Sicht, erster Teil: der Router.

### Neu
- Optional (Standard aus): die Node fragt den Router per UPnP nach seinen aktiven Port-Weiterleitungen und zeigt sie als „Aus dem Internet erreichbar?“, mit Stufe (*wahrscheinlich*, wenn das Ziel dort lauscht, sonst *unbekannt*) und Einordnung (*erwartet* oder *unerwartet*). Neue und kürzlich weggefallene Weiterleitungen sind markiert.
- „Erwartete Ports“: Ports, die du bewusst freigibst, erscheinen als erwartet.
- Die Adresse des Routers lässt sich von Hand eintragen; sie muss eine IP-Adresse im privaten Netz sein.
- Lokale API: `GET /api/exposure/overview`, `GET|POST /api/exposure/expected`, `DELETE /api/exposure/expected/{proto}/{port}`; Einstellungen und Status um UPnP erweitert.
- Hinweis: das zeigt nur, was der Router weiß. „Wahrscheinlich“ ist keine Bestätigung von außen.

## 0.1.0 – 2026-11-09

Erste Fassung (Innen-Sicht).

### Neu
- Zeigt, auf welchen Ports die Node selbst lauscht, und welches Modul den Port besitzt (ein Port ohne Besitzer erscheint als „fremdes Programm“).
- Optional: bekannte Geräte der IPAM-Subnetze per TCP-Connect auf häufige Ports prüfen (nur private Netze, je Subnetz einschaltbar).
- Lokale API unter `/api/exposure`.
