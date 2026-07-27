# RC14 Korrektur- und Installationsnachweis

Stand: 15. Juli 2026, Release Candidate `2.0.0-rc.14`

## Behobene Fehler

1. Chromium-Teildateien (`.crdownload`) sowie Firefox-/Opera-Teildateien werden nicht mehr als
   unbekannte Endformate quarantänisiert.
2. Der Minifilter setzt bei jedem Rename erneut `PENDING`. Dadurch wird dieselbe Datei-ID nach dem
   Wechsel auf den finalen Namen unter der endgültigen Dateiendung neu klassifiziert.
3. Eine deaktivierte Dateitypgruppe umgeht Hashing, Defender-/AMSI-Scan, Strukturprüfung und
   Freigabeschranke. Die UI-Aussage und das Brokerverhalten stimmen damit überein.
4. Der Broker überwacht nicht länger das allgemeine Verzeichnis `%LOCALAPPDATA%\Temp`. Dadurch
   werden Entwickler-, Installer- und Prüfwerkzeuge nicht als Downloads behandelt.
5. ProcessGuard blockiert nicht mehr allein wegen `http://`, `https://` oder `Invoke-WebRequest`.
   Verschleierung, bekannte Download-Primitiven, versteckte Netztransfers und missbrauchstypische
   LOLBin-Parameter bleiben geschützt.
6. Der Updatepfad übernimmt die gespeicherten UI-Schalter und erzwingt nicht länger ungefragt den
   Download-Ausführungsschutz. Erfolgreich angewendete signierte Policies werden in die UI-
   Zustandsdatei zurückgeschrieben.
7. MSI- und Skriptdeinstallation prüfen, dass User-Mode-Dienste und alle Treiberregistrierungen
   tatsächlich entfernt wurden. Binärdateien werden erst danach gelöscht.

## Reale Ergebnisse auf dem Entwicklungsrechner

```text
transient_browser_download_allowed=true
disabled_archive_category_bypassed=true
final_rename_reclassified=true
temp_execution_blocked=True
risky_script_blocked=True
benign_url_allowed=True
download_block_expected=False
download_interpreter_blocked=False
download_batch_blocked=False
download_policy_correct=True
```

Alle drei korrigierten Treiber wurden neu mit WDK `/W4 /WX` gebaut, lokal testsigniert, installiert
und anschließend mit `state=4 win32_exit=0` bestätigt. Broker und Core laufen als automatische
LocalSystem-Dienste. Der vom Nutzer gewünschte Zustand wurde wiederhergestellt: Download-
Ausführungsschutz aus, Archiv-Inhaltsprüfung aus; die übrigen Dateitypgruppen und die
Freigabeschranke bleiben aktiv.

## Grenzen des Nachweises

Dieser Nachweis ersetzt weder HLK/WHCP, Microsoft-Produktionstreibersignierung noch mehrtägige
Kompatibilitäts- und Dauertests. Der lokale Testbetrieb benötigt weiterhin deaktiviertes Secure
Boot und aktiviertes TESTSIGNING.
