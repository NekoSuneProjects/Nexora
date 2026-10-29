# Manual GitHub Docker builds (API and Web)

GitHub Actions > **Manual API and Web Docker Images** > Run workflow on `feat/initial-platform-foundation`. Choose `both`, `api`, or `web`. Desktop builds are not part of this workflow.

No public domain or URL is needed to build either image. The workflow builds both linux/amd64 and linux/arm64 using Buildx/QEMU. With **publish_ghcr** enabled, it pushes:

- `ghcr.io/nekosuneprojects/nexora-api:manual`
- `ghcr.io/nekosuneprojects/nexora-web:manual`

Each image also has an immutable-per-commit `dev-<12 character commit SHA>` tag (the `manual` tag will move on subsequent builds). The images will inherit the visibility and permissions of the GitHub packages; private GHCR packages require authentication via a token with read:packages permission. GitHub Actions uses `GITHUB_TOKEN` with packages:write to publish.

The build also uploads downloadable `nexora-api-docker-amd64` and `nexora-web-docker-amd64` tar.gz artifacts for offline `docker load`. These archives are **amd64 only**; pull the published GHCR image for ARM64.

## Use the images

```sh
docker pull ghcr.io/nekosuneprojects/nexora-api:manual
docker pull ghcr.io/nekosuneprojects/nexora-web:manual
```

The API needs a PostgreSQL `DATABASE_URL`, configured `HOST=0.0.0.0`, `PORT=3000`, and the schema/migrations already applied to the database. See the main deployment instructions. It is not enough to run the API image with no database. Configure `PUBLIC_BASE_URL` to match the frontend URL when one exists.

Web Nginx receives the reachable API Docker hostname at runtime using `API_UPSTREAM`, for example `http://api:3000`. Both containers must be on a network where that name resolves. Until you have a URL, test via localhost or a LAN URL. HTTPS and a correctly matched `PUBLIC_BASE_URL` are required for a public deployment.

Desktop packaging can be done later; its files are left intact but are not invoked by this new workflow.

Important: these are developer-preview builds, not a security-approved launch. E2EE remains limited.
