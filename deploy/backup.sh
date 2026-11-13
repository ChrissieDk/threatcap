#!/usr/bin/env bash
# Nightly encrypted Postgres backup. Cron: 0 3 * * * /home/opc/threatcap/deploy/backup.sh
# Needs: BACKUP_PASSPHRASE in ./.env, and `rclone` configured with a remote named "backup".
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out="${BACKUP_DIR:-$HOME/backups}/threatwatch-$stamp.sql.gz.enc"
mkdir -p "$(dirname "$out")"
docker compose -f docker-compose.prod.yml exec -T postgres pg_dump -U threatwatch threatwatch \
  | gzip \
  | openssl enc -aes-256-cbc -pbkdf2 -salt -pass env:BACKUP_PASSPHRASE -out "$out"
# Also back up the Data Protection keys: without them alert channels and sessions cannot be decrypted.
# The volume name is prefixed with the compose project (the folder name), so look it up.
dpkeys=$(docker volume ls -q --filter name=_dpkeys$ | head -n1)
[ -n "$dpkeys" ] || { echo "dpkeys volume not found" >&2; exit 1; }
docker run --rm -v "$dpkeys":/keys:ro -v "$(dirname "$out")":/out alpine \
  tar czf "/out/dpkeys-$stamp.tgz" -C /keys .
if command -v rclone >/dev/null; then rclone copy "$(dirname "$out")" backup:threatwatch --max-age 2d; fi
find "$(dirname "$out")" -type f -mtime +14 -delete
