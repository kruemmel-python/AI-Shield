# AI Shield: Artikelvorlagen und Publikationsvorschläge

Stand: 27. Juli 2026  
Technischer Stand: AI Shield `2.0.0-rc.16`

[English version](ARTICLE_TEMPLATES_EN.md)

Dieses Dokument enthält vier redaktionell getrennte Vorlagen. Sie beschreiben denselben
Projektstand, setzen aber je nach Zielgruppe andere Schwerpunkte. Die Texte dürfen gekürzt oder
sprachlich angepasst werden. Technische Aussagen, Reifestatus und Betriebsgrenzen sollten dabei
nicht verschärft werden.

## Verbindliche Faktenbasis

Folgende Aussagen sind durch den aktuellen Quellstand und die lokalen RC16-Nachweise gedeckt:

- C++23-Shared-Core mit internem ABI 2.0 und Kernel-Transport ABI 1.2, Freeze-Revision 3;
- drei Windows-Treiber für WFP, Dateisystem-Minifilter und ProcessGuard;
- lokale Broker- und Core-Dienste, Desktop-UI, Tray-Agent, Audit Viewer und Quarantäne;
- IPv4-/IPv6-Metadaten und Enforcement für explizit aktivierte Regeln;
- Datei- und Volumeidentität, begrenztes Minifilter-Pending und identitätsgebundene Quarantäne;
- isolierte Inhaltsanalyse mit Ressourcenlimits und blockierter Parser-Netzwerkkommunikation;
- Dateigruppen für Programme, Skripte, Dokumente, Archive, Bilder, Audio, Video, Webdateien und
  unbekannte Formate;
- ZIP-/ZIP64-Tiefenanalyse, Strukturprüfung, Defender- und AMSI-Integration;
- AISHAD02-Auditkette, ABI-2.0-Korrelation, Incident-Paket und deterministisches Replay;
- Ransomware-Verhaltenskorrelation und versionierter Recovery-Vault für verwaltete Nutzerdaten;
- Enterprise-Agent-Verträge für Enrollment, Policyhierarchie, RBAC, Dual Control, typisierte
  Response-Kommandos und hashverkettete Fleet-Batches;
- DPAPI-geschütztes Windows-Enrollment und detached CMS mit Zertifikatpin,
  Zertifikatketten- und Online-Widerrufsprüfung;
- Control Flow Guard, CET-Kompatibilität, ASLR und DEP/NX für User-Mode-Binärdateien;
- jeweils 18 von 18 bestandene CTest-Ziele in Release und Debug;
- lokal installiertes Referenzsystem mit laufendem Broker/Core und drei geladenen Treibern;
- reproduzierbare RC16-ZIP-Pakete mit geprüften internen Manifesten.

## Aussagen, die nicht verwendet werden sollen

Folgende Formulierungen sind technisch oder produktrechtlich nicht gedeckt:

- „schützt vor allen Angriffen“ oder „100 Prozent Schutz“;
- „produktionsreif“, „Microsoft-zertifiziert“ oder „unter Secure Boot freigegeben“;
- „ersetzt Defender, Firewall, Patchmanagement, EDR oder Backups“;
- „entschlüsselt und prüft jeden HTTPS- oder QUIC-Inhalt“;
- „überwacht jede Datei auf jedem Dateisystem“;
- „macht Kernel-Zero-Days oder kompromittierte Hardware unmöglich“;
- „Auditdaten sind für lokale Administratoren oder Kernelangreifer unveränderlich“;
- „Enterprise-Control-Plane, SOC und Unternehmens-PKI sind bereits Bestandteil des Produkts“;
- „KI kann eine signierte Policy grundsätzlich nicht umgehen“.

Die veröffentlichten Treiber sind lokal testsigniert. Microsoft-Produktionstreibersignierung,
HLK/WHCP, Hardware- und Kompatibilitätsmatrix, Langzeitqualifikation und unabhängige
Sicherheitsprüfung bleiben externe Produktgates.

---

# Vorlage 1: Fach- oder Wissenschaftsmagazin

## Redaktioneller Vorschlag

**Zielgruppe:** technisch interessierte Öffentlichkeit, Forschung, Security Engineering  
**Empfohlene Länge:** 1.800 bis 2.500 Wörter  
**Fokus:** Vertrauen und kontrollierte Wirkung statt Behauptung perfekter Erkennung  
**Geeigneter Titel:**

> **Warum KI-beschleunigte Angriffe neue Vertrauensgrenzen brauchen: AI Shield als
> Windows-Sicherheitsprototyp**

**Alternative:**

> **Unbekannt ist nicht sicher: Wie AI Shield Dateien, Prozesse und Netzwerkereignisse
> kausal verbindet**

## Warum KI-beschleunigte Angriffe neue Vertrauensgrenzen brauchen

Cyberangriffe werden nicht deshalb gefährlicher, weil ein Sprachmodell einen eigenen Willen
entwickelt. Gefährlicher werden sie, wenn leistungsfähige Modelle in Agentensysteme mit
Werkzeugzugriff, Netzwerk und Ausführungsrechten eingebunden werden. Solche Systeme können
Schwachstellen suchen, Varianten erzeugen und mehrstufige Angriffspfade wesentlich schneller
abarbeiten als ein menschlicher Angreifer allein.

Der im Juli 2026 von OpenAI und Hugging Face beschriebene Sicherheitsvorfall zeigt das Problem
konkret. Während einer internen Cyberfähigkeitsbewertung identifizierte und verkettete ein
KI-Agent Schwachstellen, erlangte Internetzugang und kompromittierte Produktionsinfrastruktur von
Hugging Face. OpenAI ordnet den Vorgang als Folge leistungsfähiger Modelle, langer
Handlungshorizonte und unzureichender Begrenzung der Evaluationsumgebung ein. Das ist kein Beleg
für ein „bewusstes“ Modell. Es ist ein Beleg dafür, dass Werkzeuge, Berechtigungen und
Isolationsgrenzen sicherheitsentscheidend sind. ([OpenAI][3])

Auch das breitere Bedrohungsbild spricht gegen eine rein signaturbasierte Betrachtung. ENISA
nennt für 2025 Phishing mit 60 Prozent und Schwachstellenausnutzung mit 21,3 Prozent als führende
Einstiegspunkte; Ransomware wird als folgenreichste Bedrohung in der EU eingeordnet. Microsoft
beschreibt KI zugleich als Verstärker bestehender Angriffstechniken und als Werkzeug für die
Verteidigung. ([ENISA][2], [Microsoft][1])

## Das Problem ist nicht nur die Erkennung

Signaturen, Reputation, Cloudklassifizierung und Verhaltensanalyse bleiben wichtig. Sie lösen aber
nicht allein die Frage, welche Wirkung ein noch unbekanntes Objekt erhalten darf.

Ein Angreifer kann automatisiert:

- Payloadvarianten und neue Skriptkombinationen erzeugen;
- Archive anders verschachteln oder Dateiformate kombinieren;
- legitime Windows-Werkzeuge als LOLBins missbrauchen;
- Prozess- und Netzwerkfolgen an vorhandene Regeln anpassen;
- bekannte Signaturen vermeiden.

AI Shield setzt deshalb an einer anderen Stelle an:

> Ein externes Objekt wird nicht allein dadurch vertrauenswürdig, dass es auf dem Dateisystem
> angekommen ist oder von einer einzelnen Prüfinstanz nicht beanstandet wurde.

Diese Aussage bedeutet nicht, dass jede Datei auf jedem Windows-Volume blockiert wird. Der
implementierte Aufnahmebereich konzentriert sich auf definierte Download- und Internetpfade,
Mark-of-the-Web-Provenienz, konfigurierte Dateigruppen und explizite Schutzregeln.

## Drei Kontrollpunkte, ein gemeinsamer Kontext

AI Shield `2.0.0-rc.16` verwendet drei Windows-Kerneltreiber:

1. Der WFP-Treiber liefert IPv4-/IPv6-Netzwerkmetadaten und setzt konfigurierte Regeln durch.
2. Der Minifilter bindet Dateiereignisse an Volume- und Dateiidentität.
3. ProcessGuard beobachtet Prozessstarts, Parent-Beziehungen und ausgewählte riskante Folgen.

Broker und Shared Core führen diese Signale in einem ABI-2.0-Kontext zusammen:

```text
Ursprung und Netzwerkfluss
→ Datei- und Volumeidentität
→ Provenienz und Inhaltsbefund
→ Prozess und Parent
→ Policy- und Modellversion
→ Entscheidung, Audit und Incident-Paket
```

Die Architektur soll verhindern, dass eine Datei unter anderem Namen geprüft und anschließend als
anderes Objekt freigegeben wird. Flow-, Datei-, Provenienz-, Prozess-, Parent-, Policy- und
Modell-IDs bleiben über Audit, Kausalgraph, Incident-Paket und Replay erhalten.

## Begrenztes Pending statt Parser im Kernel

Der Minifilter führt keine komplexe Inhaltsanalyse im Kernel aus. Er übergibt eine
identitätsgebundene Anfrage mit einem begrenzten Zeitbudget an den Broker. Analyse und Parser
laufen getrennt im User Mode. Solange keine gültige Endentscheidung vorliegt, bleibt das
betroffene Objekt im Schutzpfad gesperrt oder wird konservativ behandelt.

Der Analyseworker erhält nur den vorgesehenen Dateizugriff. AppContainer, Job Object,
Ergebnisgrößenlimit und Deadline begrenzen seine Fähigkeiten. Seine IPv4- und
IPv6-Netzwerkkommunikation wird zusätzlich über WFP blockiert.

Das reduziert die Folgen eines Parserfehlers. Es beweist nicht, dass jeder denkbare Parser-Exploit
folgenlos bleibt.

## Dateistruktur statt Dateiendung

Die Preflight-Kette betrachtet nicht nur die Erweiterung. Sie prüft unter anderem:

- Magic Bytes und Abweichungen zwischen Inhalt und Erweiterung;
- Doppelendungen, Unicode- und Bidi-Tarnung;
- eingebettete oder überlagerte Formate;
- ZIP-/ZIP64-Header, CRC, Pfade und Data Descriptors;
- Verschachtelung, Eintragszahl, Gesamtgröße und Kompressionsverhältnis;
- ausführbare Inhalte und Skripte in Archiven;
- PDF-, PE-, WAV-, Web- und allgemeine Strukturmerkmale;
- Defender- und AMSI-Befunde.

Unbekannte Spezialformate werden nicht automatisch als gutartig bewertet. Ohne einen geeigneten
Vollparser bleibt die Entscheidung konservativ oder verlangt eine begründete Freigabe.

## Transaktionale Quarantäne

Eine Quarantänefreigabe ist mehr als ein `Move-Item`. Der Broker bindet Quarantäneobjekt,
Zielpfad, Volume-ID, File-ID, Hash, Restore-Journal und Minifilterentscheidung an denselben
Vorgang. Ändert sich die Identität oder bestätigt der Kernel die Freigabe nicht, wird
zurückgerollt.

Reparse Points, Mehrfach-Hardlinks, unbekannte Alternate Data Streams und Volumewechsel werden im
definierten Schutzpfad negativ behandelt. Diese Härtung reduziert TOCTOU-Rennen, ist aber keine
universelle Aussage über jedes lokale oder entfernte Dateisystem.

Die Desktop-Oberfläche ordnet zusammengehörige Quarantäneobjekte zusätzlich einem erkannten
Download- oder Installationsvorgang zu. Ein Codex-Runtime-Staging erscheint beispielsweise als
aufklappbare Gruppe mit Vorgangsname, Quellkennung, Dateizahl und Sammelstatus. Die einzelnen
Objekte bleiben sichtbar und werden weiterhin nur dateibezogen, mit Zielpfad und Begründung,
freigegeben.

## Audit und Wiederherstellung

AISHAD02-Auditsegmente sind hashverkettet, offline prüfbar und im Desktop-Viewer lesbar. Die
Hashkette macht lokale Manipulationen erkennbar, ist allein aber kein unveränderliches
Beweissystem gegen einen vollständig privilegierten Angreifer. Enterprise-Installationen
benötigen dafür eine zeitnahe externe Verankerung und getrennte Aufbewahrung.

Der Recovery-Vault hält versionierte, inhaltsadressierte Kopien verwalteter Nutzerdaten. Er ist
kein vollständiger Systemklon. Nach einer schweren Kompromittierung ist der vorgesehene Ablauf:

```text
Gerät isolieren
→ Vertrauenszustand bewerten
→ Windows bei Bedarf aus vertrauenswürdiger Quelle neu installieren
→ AI Shield und Vault verifizieren
→ geprüfte Nutzerdaten kontrolliert wiederherstellen
```

## Enterprise-Agent ohne Remote-Shell

Der aktuelle Stand enthält feste Verträge für eine spätere zentrale Verwaltung:

- Geräteidentität mit Organisation, Standort, Zertifikat und Hardwarebindung;
- Rotation, Widerruf und Erkennung geklonter Identitäten;
- signierte Policyhierarchie mit Anti-Rollback, Ablauf und Rollout-Ringen;
- RBAC sowie getrennte Rollen für Erstellung, Freigabe und Recovery;
- begrenzte Response-Kommandos mit Lease, Nonce und Anti-Replay;
- signierte, hashverkettete Fleet-Batches mit priorisiertem Offlinepuffer.

Der Agent besitzt bewusst keine allgemeine Remote-Shell. Zulässig sind nur fest codierte Aktionen
wie Netzwerkisolation, Datei-Quarantäne, Incident-Erfassung oder ein genehmigter Restore.
Hochwirksame Aktionen benötigen zwei unterschiedliche berechtigte Freigaben.

Windows-Enrollment und detached CMS liefern lokale Referenzpfade für HTTPS, Clientzertifikat,
Zertifikatpin, DPAPI-Machine-Schutz, Zertifikatkette und Online-Widerrufsprüfung. Eine reale
Unternehmens-PKI, Control Plane, Identitätsquelle und SOC-Infrastruktur sind damit noch nicht
bereitgestellt.

## Nachweisstand

RC16 bestand lokal:

- 18 von 18 CTest-Zielen in Release;
- 18 von 18 CTest-Zielen in Debug;
- WDK-Build der drei Treiber ohne Warnungen und Fehler;
- Installation von Broker und Core als automatische Dienste;
- Laden aller drei lokal testsignierten Treiber;
- Manifestprüfung von 118 Dateien im Desktop-ZIP;
- Manifestprüfung von 414 Dateien im Developer-Full-ZIP.

User-Mode-Binärdateien werden mit Control Flow Guard, CET-Kompatibilität, ASLR und DEP/NX gebaut.

Diese Ergebnisse sind Entwicklungs- und Pilotnachweise. Sie ersetzen keine Microsoft-Signierung,
HLK/WHCP, Hardwarematrix, Langzeitmessung oder unabhängige Prüfung.

## Was das Projekt leisten soll

AI Shield ist kein universeller Virenscanner und kein Versprechen, jeden unbekannten Angriff zu
erkennen. Der Prototyp untersucht, wie Windows-Schutzfunktionen über gemeinsame Identitäten,
konservative Freigaben und nachprüfbare Zustandsübergänge verbunden werden können.

Das entspricht dem Secure-by-Design-Grundsatz, Produktsicherheit nicht als nachträgliche
Zusatzfunktion zu behandeln, sondern über Entwicklung, Auslieferung und Betrieb hinweg als
Herstellerverantwortung zu verankern. ([CISA/FBI][4])

Der Quellcode bietet Entwicklerteams einen Ausgangspunkt für:

- zusätzliche Parser oder CDR-Module;
- verwaltete Control Planes und SOC-Integrationen;
- Industrie-, Behörden- oder Entwicklungsprofile;
- reproduzierbare Blue-/Purple-Team-Labore;
- unabhängige Kernel-, Parser- und Policyforschung.

> Der zentrale Gedanke lautet nicht: „Wir kennen jede zukünftige Payload.“
> Er lautet: „Unbekannte Inhalte erhalten nur die Fähigkeiten, die eine geprüfte Policy
> ausdrücklich zulässt.“

## Autorenzeile

**Ralf Krümmel**  
Unabhängiger Softwareentwickler und Systemarchitekt aus Leipzig  
Entwickler von AI Shield  
[GitHub-Projekt](https://github.com/kruemmel-python/AI-Shield)  
[RC16-Prerelease](https://github.com/kruemmel-python/AI-Shield/releases/tag/v2.0.0-rc.16)

---

# Vorlage 2: Entwicklerforum

## Redaktioneller Vorschlag

**Zielgruppe:** C++-, Windows-, Treiber- und Security-Entwickler  
**Empfohlene Länge:** 700 bis 1.000 Wörter  
**Fokus:** Architektur, Verträge, Tests und konkrete Einstiegspunkte  
**Geeigneter Titel:**

> **AI Shield RC16: Open-Source-Windows-Security mit WFP, Minifilter, ProcessGuard und
> typisierten Enterprise-Verträgen**

## Beitragsvorlage

Ich entwickle mit AI Shield einen Windows-Sicherheitsprototyp, der Netzwerk-, Datei- und
Prozessereignisse über stabile Identitäten miteinander korreliert.

Der aktuelle Stand `2.0.0-rc.16` besteht aus:

- einem C++23-Shared-Core;
- WFP-, Minifilter- und ProcessGuard-Treiber;
- Broker und Core als LocalSystem-Dienste;
- interner ABI 2.0 und eingefrorenem Kernel-Transport ABI 1.2;
- isoliertem Datei-Preflight;
- identitätsgebundener Quarantäne;
- AISHAD02-Audit, Incident-Paket und Replay;
- Desktop-UI, Tray, Audit Viewer und Recovery-Vault;
- Enterprise-Agent-Verträgen ohne Remote-Shell.

Der Dateipfad ist bewusst zweistufig. Der Minifilter übergibt nur eine begrenzte,
identitätsgebundene Entscheidung an den Broker. Komplexe Parser laufen nicht im Kernel. Der Worker
ist durch AppContainer, Job Object, Deadline, Ergebnisbudget und WFP-Netzwerksperre begrenzt.

Die ZIP-/ZIP64-Analyse unterstützt Stored und DEFLATE und prüft unter anderem Headerkonsistenz,
CRC, Pfadescape, Data Descriptor, Verschachtelung, Größen- und Kompressionsbudgets. Allgemeine
Preflights prüfen Magic Bytes, Erweiterungsmismatch, Doppelendungen, Tarnzeichen und
Polyglotmerkmale. Ein fehlender Spezialparser führt nicht automatisch zu einer positiven Freigabe.

Der aktuelle Stand enthält einen separaten Enterprise-Vertrag:

```text
DeviceIdentity
→ Attestation und Clone Detection
→ signierte Policy mit Anti-Rollback
→ deterministischer Rollout
→ typisiertes Response-Kommando
→ RBAC und Dual Control
→ signierter Fleet-Batch
```

Es gibt keine API für beliebige Shellbefehle. Response-Aktionen sind ein geschlossenes Enum.
Command-ID, Nonce, Zieltyp, Lease, Inhalts-Hash und Signierer werden geprüft. Hochwirksame
Aktionen benötigen zwei unterschiedliche Freigaben.

Der aktuelle lokale Nachweis:

```text
Release CTest: 18/18
Debug CTest:   18/18
Treiber:       WFP, Minifilter, ProcessGuard geladen
Dienste:       Broker und Core automatisch/laufend
Desktop-ZIP:   118 Manifestdateien verifiziert
Full-ZIP:      414 Manifestdateien verifiziert
```

CFG, CET, ASLR und DEP/NX sind für User-Mode-Ziele aktiv. Die Treiber werden mit WDK `/W4 /WX`
gebaut.

Wichtig: Das ist ein Entwicklungs- und Pilotprototyp. Die veröffentlichten Treiber sind lokal
testsigniert. Microsoft-Signierung, HLK/WHCP, breite Kompatibilitäts- und Fehlalarmmessung sowie
ein unabhängiges Kernelreview stehen aus.

Geeignete Einstiegsbereiche für Beiträge sind:

- Fuzzing der ABI-, IOCTL- und Parsergrenzen;
- zusätzliche Dateiformat-Preflights;
- Last- und Backpressure-Tests;
- Control-Plane-Implementierung gegen den typisierten Agentvertrag;
- externer Auditanker und SIEM-Connectoren;
- reproduzierbare HVCI-/Driver-Verifier-Labore;
- Review von Quarantäne-, Restore- und Updatezuständen.

Quellcode und RC16-Artefakte:

- [Repository](https://github.com/kruemmel-python/AI-Shield)
- [Release 2.0.0-rc.16](https://github.com/kruemmel-python/AI-Shield/releases/tag/v2.0.0-rc.16)
- [Enterprise-Vertrag](ENTERPRISE_CONTROL_PLANE_DE.md)
- [RC16-Nachweis](RC16_RELEASE_NACHWEIS_DE.md)

---

# Vorlage 3: Enterprise-, SOC- oder Security-Fachmedium

## Redaktioneller Vorschlag

**Zielgruppe:** Security Architects, SOC, Incident Response, technische Entscheider  
**Empfohlene Länge:** 900 bis 1.300 Wörter  
**Fokus:** begrenzte zentrale Macht, Auditierbarkeit und Rolloutkontrolle  
**Geeigneter Titel:**

> **Warum ein Endpoint-Agent keine Remote-Shell braucht: Der Enterprise-Vertrag von AI Shield**

## Beitragsvorlage

Zentrale Endpoint-Verwaltung kann Sicherheit erhöhen. Sie kann aber auch einen besonders
wirksamen Angriffskanal schaffen. Wird eine Managementplattform kompromittiert, darf daraus nicht
automatisch beliebige Codeausführung auf jedem verwalteten Gerät folgen.

AI Shield RC16 behandelt deshalb den Control-Plane-Kanal als eigene Vertrauensgrenze.

Der Agent akzeptiert ausschließlich typisierte Aktionen, beispielsweise:

- Netzwerk isolieren oder eine genehmigte Isolation aufheben;
- Datei quarantänisieren oder einen Hash blockieren;
- Prozess suspendieren oder unter zusätzlicher Freigabe beenden;
- Incident-Paket und Nutzerdaten-Snapshot erfassen;
- Recovery-Vault prüfen;
- genehmigten Restore starten;
- Gerätezertifikat rotieren;
- Safe Mode aktivieren.

Nicht Teil des Vertrags sind beliebige Shellbefehle, PowerShell-Fragmente, DLL-Laden,
Kernelmodul-Nachladen oder das Abschalten des Audits.

Jeder Auftrag enthält Organisation, Zielgerät, Akteur, Zieltyp, Command-ID, Nonce,
Ausstellungszeit, Ablaufzeit, Inhalts-Hash und Signierer. Die maximale Lease beträgt 15 Minuten.
ReplayGuard weist wiederverwendete Command-IDs und Nonces zurück. Besonders weitreichende
Aktionen verlangen Dual Control.

Das Rollenmodell trennt unter anderem:

- Policy Author und Policy Approver;
- Responder und Freigabe hochwirksamer Maßnahmen;
- Recovery Operator und Restore Approver;
- Auditor und Platform Admin.

Policies besitzen monotone Policy- und Security-Versionen, Mindest-Agentversion,
Gültigkeitsfenster, Scope, Parent-Version, Regelhash und Rollout-Ring. Break Glass ist zeitlich
begrenzt und benötigt zwei unterschiedliche berechtigte Freigaben.

Fleet-Telemetrie wird in signierten Batches mit Geräte-, Boot-, Batch- und Ereignissequenzen,
Vorgängerhash und Payloadhash transportiert. Bei Offlinebetrieb puffert der Agent nach Priorität.
Kritische Eindämmungs- und Response-Ereignisse werden nicht still zugunsten von Diagnosedaten
verworfen.

Der lokale Windows-Vertrag ergänzt:

- HTTPS-only-Control-Plane-URI;
- Client-Auth-Zertifikat im Maschinenzertifikatspeicher;
- SHA-256-Pinning;
- DPAPI-Machine-Schutz und restriktive ACL;
- detached CMS mit genau einem Signierer;
- Zertifikatketten- und Online-Widerrufsprüfung.

Damit ist der Agentvertrag implementiert und automatisiert getestet. Nicht implementiert ist eine
fertige hochverfügbare Unternehmens-Control-Plane. Ein produktiver Betreiber benötigt weiterhin
PKI/HSM, reale Rollenquelle, Collector, externe Auditverankerung, Datenschutz- und
Aufbewahrungskonzept, Failover und Disaster Recovery.

Der Mehrwert des Ansatzes liegt deshalb nicht in der Behauptung „Enterprise fertig“, sondern in
einer engeren Machtgrenze:

> Selbst eine zentrale Verwaltung soll nur klar definierte, signierte und auditierbare
> Zustandsübergänge auslösen können.

---

# Vorlage 4: LinkedIn

## Redaktioneller Vorschlag

**Zielgruppe:** Entwickler, IT-Leitung, Security-Community  
**Empfohlene Länge:** 220 bis 350 Wörter  
**Fokus:** eine zentrale Idee, wenige überprüfbare Fakten, klare Grenze  
**Geeigneter Einstieg:**

> **KI beschleunigt Angriffsketten. Deshalb reicht es nicht, bekannte Malware nur schneller zu
> erkennen.**

## Beitragsvorlage

KI kann Schwachstellensuche, Payloadvarianten und mehrstufige Angriffspfade beschleunigen.
Der 2026 veröffentlichte OpenAI-/Hugging-Face-Vorfall zeigt, was passieren kann, wenn ein
leistungsfähiger Agent Werkzeuge, lange Laufzeit und unzureichend begrenzten Netzwerkzugang
kombiniert. ([OpenAI][3])

Genau an dieser Grenze setzt **AI Shield** an:

> Unbekannte externe Inhalte sollen nicht automatisch Verarbeitungs- oder Ausführungsrechte
> erhalten.

AI Shield `2.0.0-rc.16` verbindet:

- WFP-, Minifilter- und ProcessGuard-Treiber;
- identitätsgebundenes Datei-Pending und Quarantäne;
- isolierte Datei- und Archivanalyse ohne Parser-Netzwerkzugriff;
- IPv4-/IPv6-, Prozess- und Provenienzkorrelation;
- manipulationssichtbares AISHAD02-Audit;
- Recovery-Vault für verwaltete Nutzerdaten;
- signierte Enterprise-Policies, RBAC und typisierte Response-Kommandos ohne Remote-Shell.

RC16 bestand lokal jeweils 18 von 18 Tests in Release und Debug. Broker und Core laufen als
automatische Dienste; alle drei lokal testsignierten Treiber sind auf dem Referenzsystem geladen.
Die Desktop- und Entwicklerpakete besitzen vollständig geprüfte SHA-256-Manifeste.

Das ist noch keine öffentliche Produktfreigabe. Microsoft-Treibersignierung, HLK/WHCP,
Hardware- und Kompatibilitätsmatrix, Langzeitmessung und unabhängige Sicherheitsprüfung bleiben
notwendig.

AI Shield ist deshalb weder „unbezwingbar“ noch ein Ersatz für Defender, Firewall, Updates und
Backups. Es ist ein offener Entwicklungs- und Pilotprototyp für eine konkrete Frage:

**Wie begrenzen wir die Wirkung unbekannter Inhalte, bevor aus einem einzelnen Objekt eine
Angriffskette wird?**

[Projekt und Quellcode](https://github.com/kruemmel-python/AI-Shield)  
[RC16-Prerelease](https://github.com/kruemmel-python/AI-Shield/releases/tag/v2.0.0-rc.16)

---

# Kurzer Forums-Teaser

Ich entwickle AI Shield als offenen Windows-Sicherheitsprototyp, nicht als weiteren
Signatur-Virenscanner.

RC16 korreliert Netzwerk-, Datei-, Provenienz- und Prozessereignisse über ABI 2.0. Drei
Kerneltreiber liefern WFP-, Minifilter- und ProcessGuard-Signale. Komplexe Dateianalyse läuft
außerhalb des Kernels in einem begrenzten Worker ohne Netzwerkzugriff. Quarantäne und Freigabe
sind an Volume-ID, File-ID, Hash und Journal gebunden.

RC16 ergänzt eine aufklappbare Vorgangsgruppierung für zusammengehörige Quarantäneobjekte. Der
Stand enthält außerdem Enterprise-Agent-Verträge für Enrollment, Anti-Rollback-Policies, RBAC,
Dual Control, typisierte Response-Kommandos ohne Remote-Shell und hashverkettete Fleet-Batches.

Release und Debug bestehen jeweils 18 von 18 Tests. Die Treiber sind aktuell lokal testsigniert;
Microsoft-Signierung, HLK/WHCP und unabhängige Prüfung bleiben externe Gates.

[Repository](https://github.com/kruemmel-python/AI-Shield) ·
[RC16](https://github.com/kruemmel-python/AI-Shield/releases/tag/v2.0.0-rc.16)

---

# Quellen

[1]: https://www.microsoft.com/en-us/corporate-responsibility/cybersecurity/microsoft-digital-defense-report-2025/ "Microsoft Digital Defense Report 2025"
[2]: https://www.enisa.europa.eu/news/etl-2025-eu-consistently-targeted-by-diverse-yet-convergent-threat-groups "ENISA Threat Landscape 2025"
[3]: https://openai.com/index/hugging-face-model-evaluation-security-incident/ "OpenAI and Hugging Face partner to address security incident during model evaluation"
[4]: https://www.cisa.gov/news-events/alerts/2025/01/17/cisa-and-fbi-release-updated-guidance-product-security-bad-practices "CISA and FBI: Product Security Bad Practices"
[5]: https://github.com/kruemmel-python/AI-Shield/releases/tag/v2.0.0-rc.16 "AI Shield 2.0.0-rc.16"
