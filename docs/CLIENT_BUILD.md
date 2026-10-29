# Nexora manual client builds

No domain is required to build either client. The web container proxies /api and /gateway to the backend configured via API_UPSTREAM; the desktop app asks for your deployed frontend URL on first launch. The GitHub Actions **Manual Web and Desktop Builds** workflow runs only via Actions > Run workflow, not on every commit.

## Web container

```sh
docker compose -f docker-compose.frontend.yml up -d --build
```

Set `FRONTEND_BIND=0.0.0.0` only if you want LAN access; by default it binds `127.0.0.1:8080`. Set `API_UPSTREAM=http://api:3000` for a reachable backend (its Docker host/service name) before running the web container. Example: `API_UPSTREAM=http://192.168.1.10:3000 FRONTEND_PORT=8080 docker compose -f docker-compose.frontend.yml up -d --build`.

**Important:** the API's `PUBLIC_BASE_URL` must match the URL users actually open in the web client, not the upstream API hostname. This ensures the Gateway's returned websocket address is correct and the Origin policy matches. Configure trusted proxy CIDRs rather than trusting unvalidated X-Forwarded headers. Use HTTPS and wss on public domains.

## Desktop

Linux manual build in Docker:

```sh
docker build -f Dockerfile.desktop -t nexora-desktop-builder .
mkdir -p desktop-dist
docker run --rm -v "$PWD/desktop-dist:/artifacts" nexora-desktop-builder
```

Outputs a Linux AppImage under `desktop-dist/`. Windows installers are built by the manual GitHub Actions Windows job, or directly on a Windows machine: `cd apps/desktop && npm install && npm run build:win`.

The URL is **not** baked into either installer. On first desktop launch, enter your Nexora **frontend** URL. This initial client stores it in the Electron userData directory. Remote URLs must use HTTPS; localhost HTTP is permitted for local testing. To switch backend, update the stored settings file or remove it and relaunch. The optional workflow URL field is informational; do not put secrets in it. This initial desktop client is an Electron web wrapper; screen sharing, native voice/video, auto-update and signed binaries are NOT included.

## Security and testing

Desktop packages are unsigned developer builds. Verify artifacts yourself and do not redistribute them as production secure releases. Nexora E2EE remains experimental, with unreviewed multi-device trust and membership recovery.
