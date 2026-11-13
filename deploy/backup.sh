#!/usr/bin/env bash
# Nightly encrypted Postgres backup. Cron: 0 3 * * * /opt/threatwatch/deploy/backup.sh
# Needs: BACKUP_PASSPHRASE in ./.env, and `rclone` configured with a remote named "backup".
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out="/var/backups/threatwatch/threatwatch-$stamp.sql.gz.enc"
mkdir -p "$(dirname "$out")"
docker compose -f docker-compose.prod.yml exec -T postgres pg_dump -U threatwatch threatwatch \
  | gzip \
  | openssl enc -aes-256-cbc -pbkdf2 -salt -pass env:BACKUP_PASSPHRASE -out "$out"
# Also back up the Data Protection keys: without them alert channels and sessions cannot be decrypted.
docker run --rm -v threatwatch_dpkeys:/keys:ro -v "$(dirname "$out")":/out alpine \
  tar czf "/out/dpkeys-$stamp.tgz" -C /keys .
if command -v rclone >/dev/null; then rclone copy "$(dirname "$out")" backup:threatwatch --max-age 2d; fi
find "$(dirname "$out")" -type f -mtime +14 -delete
