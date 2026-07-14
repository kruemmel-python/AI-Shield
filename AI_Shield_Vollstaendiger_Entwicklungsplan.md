# AI Shield – Vollständiger Entwicklungsplan

Die maßgebliche, formatierte Fassung befindet sich in der beigefügten DOCX-Datei. Dieses Markdown-Dokument dient als maschinenlesbarer Begleitindex.

## Verbindliche Eckpunkte

- Windows-first: Windows 11 Pro/Enterprise 25H2 und 26H1, x64.
- Produktcode ausschließlich C++.
- Userspace C++23; Kernel eingeschränktes WDK-C++ mit `/kernel`.
- Keine C++-Exceptions oder RTTI in sicherheitskritischen Komponenten.
- WFP, Minifilter und Prozesscallbacks sind Sensoren und Durchsetzungsadapter, aber Windows ist nicht Root of Trust.
- Risikoabhängige Shadow-Ausführung in AppContainer und Hyper-V-Isolation.
- Kausale Herkunftsverfolgung von Flow über Datei bis Prozess und Egress.
- Signierte, unveränderliche Produktionsmodelle; kein Online-Lernen.
- Linux-Portierung über austauschbare Plattformadapter.
- Zweiter Produktzweig: AI Shield Sovereign mit eigener Security Domain vor Windows.

## Dokumentstruktur

1. Verbindliche Produktentscheidungen
2. Zielbild, Nutzen und Nicht-Ziele
3. Bedrohungsmodell
4. Vertrauensmodell und unbekannte Windows-Lücken
5. Zielplattform
6. Gesamtarchitektur
7. Datenfluss
8. Komponentenspezifikation
9. ABI und Datenmodelle
10. Sichere C++-Regeln
11. Ressourcenmodell
12. Erkennungs- und KI-Architektur
13. Sandbox
14. Policy
15. Audit und Datenschutz
16. Funktionale Anforderungen
17. Nichtfunktionale Anforderungen
18. Repository und Build
19. Arbeitspakete
20. Teammodell
21. Zeitplan
22. Test und Zertifizierung
23. Installation und Update
24. Incident Response
25. Linux-Erweiterbarkeit
26. Sovereign Mode
27. Risikoregister
28. Definition of Done
