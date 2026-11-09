# Änderungen – Exposure-Check

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
