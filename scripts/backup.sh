#!/bin/sh
# T0.8 — Backup diário off-site do AgilFac (roda no VPS via cron às 02:00 de Brasília).
# 1) cópia consistente dos bancos (VACUUM INTO, dentro do container)
# 2) compacta e criptografa (AES-256, chave em /root/.agilfac-backup.key)
# 3) guarda no servidor (backups/ e backups/mensal/) para download pelo superadmin
#    e, se AGILFAC_BACKUP_REMOTE estiver definido, envia também via rclone
# 4) retenção: 30 diários + 12 mensais
#
# Hoje: só local (download pelo painel superadmin). Plano: Google Drive e depois
# Backblaze B2 ao chegar em 10 clientes — basta definir AGILFAC_BACKUP_REMOTE.
set -u

APP=/opt/agilfac
CONTAINER=agilfac-agilfac-1
KEY=/root/.agilfac-backup.key
REMOTE=${AGILFAC_BACKUP_REMOTE:-}
STAMP=$(TZ=America/Sao_Paulo date +%Y-%m-%d_%H%M)
DAY=$(TZ=America/Sao_Paulo date +%d)

log() { echo "$(TZ=America/Sao_Paulo date '+%Y-%m-%d %H:%M:%S') $*"; }
fail() { log "ERRO: $*"; exit 1; }

[ -s "$KEY" ] || fail "chave de criptografia não encontrada em $KEY"
[ -z "$REMOTE" ] || command -v rclone >/dev/null || fail "rclone não instalado"

cd "$APP" || fail "pasta $APP não existe"
mkdir -p backups
WD=$(docker inspect -f '{{range .Mounts}}{{if eq .Source "'"$APP"'"}}{{.Destination}}{{end}}{{end}}' "$CONTAINER")
[ -n "$WD" ] || fail "não achei o volume $APP no container"

SNAP="backups/snap-$STAMP"
OUT=$(docker exec -w "$WD" "$CONTAINER" node scripts/backup.js "$SNAP" 2>&1)
RC=$?
echo "$OUT" | grep -v -i experimental | grep -v trace-warnings
[ $RC -eq 0 ] && [ -f "$SNAP/master.sqlite" ] || { rm -rf "$SNAP"; fail "cópia dos bancos falhou"; }

FILE="backups/agilfac-$STAMP.tar.gz.enc"
tar -czf - -C backups "snap-$STAMP" | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass "file:$KEY" -out "$FILE" \
  || fail "compactação/criptografia falhou"
rm -rf "$SNAP"

chmod 600 "$FILE"
mkdir -p backups/mensal
[ "$DAY" = "01" ] && cp -p "$FILE" backups/mensal/
find backups -maxdepth 1 -name 'agilfac-*.tar.gz.enc' -mtime +30 -delete
find backups/mensal -maxdepth 1 -name 'agilfac-*.tar.gz.enc' -mtime +370 -delete

if [ -n "$REMOTE" ]; then
  rclone copy "$FILE" "$REMOTE/diario/" || fail "envio para $REMOTE falhou"
  [ "$DAY" = "01" ] && { rclone copy "$FILE" "$REMOTE/mensal/" || fail "envio mensal falhou"; }
  rclone delete "$REMOTE/diario/" --min-age 31d >/dev/null 2>&1
  rclone delete "$REMOTE/mensal/" --min-age 370d >/dev/null 2>&1
fi

log "OK: $(basename "$FILE") ($(du -h "$FILE" | cut -f1)) salvo${REMOTE:+ e enviado para $REMOTE}"
