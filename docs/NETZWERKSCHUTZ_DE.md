# AI Shield: Systemweiter Netzwerkschutz

Stand: 13. Juli 2026, Kernel-Transport ABI 1.2

## Schutzumfang

`AIShieldWfp.sys` registriert Callouts fuer ausgehende Verbindungsaufbauten und eingehende
Verbindungsannahmen auf den ALE-Schichten von Windows Filtering Platform. Erfasst werden IPv4 und
IPv6 sowie TCP und UDP. Der Schutz ist damit nicht auf den HTTP-Gateway-Port beschraenkt. Der
Kernel liefert Prozess-ID, lokale und entfernte Ports, Transportprotokoll und eine
datensparsame Kennung der entfernten Adresse ueber ABI 1.2 an den Broker.

Der sichere Ein-Klick-Start `AI_Shield_Protect_System.cmd` aktiviert eine signierte Enforcement-
Policy. Sie blockiert bekannte laterale Bewegungs- und Wurm-Ausbreitungspfade ueber RPC, NetBIOS,
SMB und RDP. Die strengere Variante `AI_Shield_Protect_System_Strict.cmd` blockiert zusaetzlich
unaufgeforderte eingehende Verbindungen und Browser-Verbindungen ausserhalb DNS, HTTP, HTTPS und
DNS-over-TLS. Diese Variante kann VPNs, lokale Entwicklungsserver, Browser-Erweiterungen und
Unternehmensanwendungen beeintraechtigen und muss vor breitem Einsatz mit Allowlists getestet werden.

Der HTTP-Gateway bleibt ein separater Schutzpfad fuer lesbare HTTP-Anfragen. Er bewertet Inhalte,
normalisiert Anfragen und kann riskante Anfragen verwerfen. WFP kontrolliert dagegen die
systemweiten Netzwerk-Flows unabhaengig davon, ob der Gateway verwendet wird.

## Verschluesselter Verkehr

HTTPS und QUIC werden auf Flow- und Metadatenebene erfasst und kontrolliert. AI Shield entschluesselt
TLS oder QUIC nicht und installiert absichtlich keine lokale Man-in-the-Middle-Zertifizierungsstelle.
Ohne Browser-/Endpoint-Integration oder einen explizit verwalteten TLS-Proxy kann kein Produkt den
verschluesselten Anwendungsinhalt transparent untersuchen. DNS-, TLS- und QUIC-Parser im Projekt
werten nur Daten aus, die einem Sensor im Klartext beziehungsweise als zulaessige Metadaten
vorliegen.

## Startmodi

```powershell
# Empfohlener systemweiter Schutz; beide Befehle sind gleichwertig
.\AI_Shield_Start.cmd
.\AI_Shield_Protect_System.cmd

# Strenger Pilotmodus mit hoeherem Kompatibilitaetsrisiko
.\AI_Shield_Protect_System_Strict.cmd

# Status
build_vs\Release\ai_shield_driverctl.exe status
build_vs\Release\ai_shield_kernelctl.exe status
```

Absolute Sicherheit gegen alle Angriffe ist technisch nicht erreichbar. AI Shield reduziert die
Angriffsflaeche als Defense-in-Depth-Schicht; Windows Update, Defender/EDR, Firewall, Least Privilege,
Anwendungsallowlisting und sichere Backups bleiben erforderlich.
