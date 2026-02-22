#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/smite"
BACKUP_DIR="/opt/smite_backup_$(date +%F-%H%M%S)"
REPO_SSH_URL="git@github.com:pakrokh/ssm.git"

echo "[1/8] Stopping old containers..."
docker rm -f smite-frontend smite-panel smite-nginx >/dev/null 2>&1 || true

if [[ -d "${APP_DIR}" ]]; then
  echo "[2/8] Backing up current deployment to ${BACKUP_DIR}..."
  mv "${APP_DIR}" "${BACKUP_DIR}"
else
  echo "[2/8] No existing /opt/smite directory found"
fi

echo "[3/8] Fresh clone from ${REPO_SSH_URL}..."
git clone "${REPO_SSH_URL}" "${APP_DIR}"
cd "${APP_DIR}"

echo "[4/8] Restoring env/data/certs from backup if available..."
if [[ -f "${BACKUP_DIR}/.env" ]]; then
  cp "${BACKUP_DIR}/.env" .env
else
  cp .env.example .env
fi
mkdir -p panel/data panel/certs
cp -a "${BACKUP_DIR}/panel/data/." panel/data/ >/dev/null 2>&1 || true
cp -a "${BACKUP_DIR}/panel/certs/." panel/certs/ >/dev/null 2>&1 || true

echo "[5/8] Verifying required files..."
test -f panel/app/tunnel_projects.py
grep -q '@router.get("/providers")' panel/app/routers/tunnels.py
grep -q 'const DEFAULT_TUNNEL_PROJECTS' frontend/src/pages/Tunnels.tsx

echo "[6/8] Rebuilding panel image from local source..."
docker compose down --remove-orphans >/dev/null 2>&1 || true
docker compose build --no-cache smite-panel

echo "[7/8] Starting panel..."
docker compose up -d --force-recreate smite-panel

echo "[8/8] Runtime verification..."
docker exec smite-panel sh -lc 'test -f /app/app/tunnel_projects.py'
docker exec smite-panel sh -lc 'grep -q "@router.get(\"/providers\")" /app/app/routers/tunnels.py'

echo
echo "Providers API response:"
curl -s http://127.0.0.1:8000/api/tunnels/providers
echo
echo
echo "Done. Hard refresh browser (Ctrl+Shift+R)."
