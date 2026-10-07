# DIDSSO mit Docker bereitstellen

Die Laufzeit besteht aus fünf Images:

- `idp-web`: HTTPS-Webseite des Identity Providers
- `idp-didcomm`: DIDComm-Backend und RISC-Zero-Verifikation
- `rp-web`: Webseite des Relying Party
- `rp-didcomm`: DIDComm-Backend und RISC-Zero-Prover
- `wallet-backend`: lokales Backend der Firefox-Erweiterung

Die Firefox-Erweiterung selbst läuft weiterhin in Firefox und wird nicht in
einen Container verschoben. Alle Images werden für `linux/amd64` gebaut. Sie
laufen dadurch auch unter Docker Desktop auf einem Apple-Silicon-Mac, dort
allerdings per Emulation. Besonders die Beweiserstellung kann dort langsamer
sein.

## Voraussetzungen für den einmaligen Build

1. Docker Desktop starten und Linux-Container verwenden.
2. Einen GitHub-Account und ein Personal Access Token mit mindestens
   `write:packages` und `read:packages` anlegen.
3. PowerShell im DIDSSO-Projektordner öffnen.

## Images einmalig bauen und veröffentlichen

Zuerst die Beispielkonfiguration kopieren:

```powershell
Copy-Item .env.example .env
```

In `.env` `YOUR_GITHUB_USERNAME` durch den eigenen GitHub-Namen ersetzen. Der
Name sollte kleingeschrieben werden. `DIDSSO_VERSION` ist der unveränderliche
Versions-Tag, zum Beispiel `1.0.0`.

Danach bei der GitHub Container Registry anmelden:

```powershell
$env:CR_PAT = "DEIN_GITHUB_TOKEN"
$env:CR_PAT | docker login ghcr.io -u DEIN_GITHUB_NAME --password-stdin
Remove-Item Env:CR_PAT
```

Alle Images bauen:

```powershell
docker compose -f compose.yaml -f compose.build.yaml build
```

Optional kann danach geprüft werden, ob das im Image enthaltene
RISC-Zero-Programm ansprechbar ist:

```powershell
docker compose -f compose.yaml -f compose.build.yaml run --rm --no-deps rp-didcomm /usr/local/bin/credential-risc0 method-id
```

Der erste RISC-Zero-Build kann lange dauern und mehrere Gigabyte
Zwischenspeicher benötigen. Die Toolchain und das Guest-Programm werden dabei
im Builder-Container kompiliert; sie müssen nicht auf dem Zielsystem installiert
sein.

Das System vor dem Veröffentlichen lokal starten:

```powershell
docker compose -f compose.yaml -f compose.build.yaml up -d
docker compose ps
docker compose logs -f
```

Mit `Strg+C` wird nur die Loganzeige beendet. Die Container laufen weiter. Die
IdP-Seite nutzt ein selbst signiertes Zertifikat. Deshalb zuerst
`https://127.0.0.1:3001` öffnen und die lokale Zertifikatswarnung akzeptieren.
Danach ist der RP unter `http://127.0.0.1:3002` erreichbar.

Wenn der Test erfolgreich ist, alle fünf Images hochladen:

```powershell
docker compose -f compose.yaml -f compose.build.yaml push
```

In GitHub unter `Packages` die fünf Pakete anschließend auf `Public` stellen,
damit Empfänger sich nicht bei GHCR anmelden müssen.

## Nutzung auf einem anderen Rechner

Der Empfänger benötigt nur Git, Docker Desktop und Firefox, nicht jedoch Rust,
Python, WSL oder die RISC-Zero-Toolchain.

```powershell
git clone URL_DES_REPOSITORY
Set-Location DIDSSO
Copy-Item .env.example .env
```

In `.env` müssen exakt derselbe Registry-Namespace und Versions-Tag wie beim
Veröffentlichen stehen. Danach werden ausschließlich die fertigen Images
geladen und gestartet:

```powershell
docker compose pull
docker compose up -d
docker compose ps
```

Auf macOS/Linux entsprechen die letzten Befehle denselben Docker-Befehlen; nur
das Kopieren heißt dort `cp .env.example .env`.

Die Firefox-Erweiterung wird aus `firefox-extension` als temporäres Add-on in
`about:debugging` geladen. Anschließend einmal die IdP-Seite öffnen, das lokale
Zertifikat akzeptieren und den Flow über die RP-Seite starten.

## Stoppen und Daten verwalten

Container stoppen, die persistenten Identitäten und Konten aber behalten:

```powershell
docker compose down
```

Logs anzeigen:

```powershell
docker compose logs -f idp-didcomm rp-didcomm wallet-backend
```

Vollständiger Reset einschließlich Wallet, DIDs, Schlüssel, Nutzer und
Sessions:

```powershell
docker compose down --volumes
```

Der letzte Befehl löscht den Prototypzustand unwiderruflich. Ohne `--volumes`
bleiben die Daten in den Volumes `idp-data`, `rp-data` und `wallet-data`
erhalten.
