# DIDSSO Prototype

This repository contains the Docker Compose configuration for the DIDSSO
prototype and the Firefox extension required to use it.

The reproducible local performance-measurement procedure is documented in
[evaluation/EVALUATION.md](evaluation/EVALUATION.md).

## Requirements

- Git
- Docker Desktop with Docker Compose
- Firefox

The published images target `linux/amd64`. No local Python, Rust, RISC Zero, or
WSL installation is required to run them.

Tested with:

- Docker Desktop 4.94.0
- Docker CLI 29.8.2
- Docker Compose v5.5.1
- Firefox 157.0

## Download and Start the Containers

Clone the repository so that both the Compose files and the Firefox extension
are available:

```powershell
git clone https://github.com/mrvnplz/DIDSSO.git
cd DIDSSO
```

Create a `.env` file.

PowerShell:

```powershell
Copy-Item .env.example .env
```

macOS/Linux:

```bash
cp .env.example .env
```

The file must contain the published GHCR namespace and image version:

```dotenv
DIDSSO_REGISTRY=ghcr.io/mrvnplz
DIDSSO_VERSION=1.0.1
```

The packages are public, so no GHCR login is required. Pull and start all five
containers from a terminal:

```text
docker compose pull
docker compose up -d
docker compose ps
```

Open the IdP first at <https://127.0.0.1:3001>. It uses a self-signed TLS
certificate, so Firefox displays a certificate warning on the first visit.
Accept this warning for the local prototype. Docker Desktop may display a link
using `http://127.0.0.1:3001` because it cannot infer the application protocol
from a TCP port mapping. The IdP must nevertheless be opened using **HTTPS**.

The RP is available at <http://127.0.0.1:3002>.

Useful commands:

```text
docker compose logs -f
docker compose down
```

`docker compose down` retains the persistent prototype data. The command
`docker compose down --volumes` additionally deletes users, DIDs, keys,
sessions, and token grants. Use it only when an intentional full reset is
required.

## Load and Use the Firefox Extension

The extension itself runs in Firefox and is not included in a container. Its
local wallet backend is already started by Docker as `wallet-backend` on
`127.0.0.1:8765`.

1. Download the repository, or at least its `firefox-extension` directory.
2. Open `about:debugging#/runtime/this-firefox` in Firefox by entering it into the search bar.
3. Select **Load Temporary Add-on**.
4. Select `firefox-extension/manifest.json`.
5. Open the DIDSSO extension from the Firefox toolbar. Its status should show
   that the wallet backend is reachable.
6. Leave automatic DID management enabled for the normal flow. The extension
   then selects an existing pairwise DID for the current RP or prepares a new
   one when a DID registration or SSO flow is started.
7. Open <http://127.0.0.1:3002> and start the desired DID registration or login
   flow from the RP page.

Firefox loads the extension only temporarily. After restarting Firefox, repeat
steps 2 through 4.
