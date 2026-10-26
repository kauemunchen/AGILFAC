#!/bin/sh
# T0.8 — Teste de restauração: pega o backup mais recente (local ou remoto), descriptografa
# numa pasta temporária e confere a integridade de cada banco e a contagem de OPs.
# NÃO mexe nos bancos em uso.
set -u

APP=/opt/agilfac
CONTAINER=agilfac-agilfac-1
KEY=/root/.agilfac-backup.key
REMOTE=${AGILFAC_BACKUP_REMOTE:-}
TMP="backups/restore-test"

log() { echo "$(TZ=America/Sao_Paulo date '+%Y-%m-%d %H:%M:%S') $*"; }
fail() { log "ERRO: $*"; rm -rf "$APP/$TMP"; exit 1; }

cd "$APP" || exit 1
rm -rf "$TMP" && mkdir -p "$TMP"
if [ -n "$REMOTE" ]; then
  LATEST=$(rclone lsf "$REMOTE/diario/" --files-only 2>/dev/null | sort | tail -1)
  [ -n "$LATEST" ] || fail "nenhum backup encontrado em $REMOTE/diario/"
  rclone copy "$REMOTE/diario/$LATEST" "$TMP/" || fail "download falhou"
else
  LATEST=$(ls -1 backups/agilfac-*.tar.gz.enc 2>/dev/null | sort | tail -1 | xargs -r basename)
  [ -n "$LATEST" ] || fail "nenhum backup encontrado em $APP/backups"
  cp "backups/$LATEST" "$TMP/"
fi
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass "file:$KEY" -in "$TMP/$LATEST" | tar -xzf - -C "$TMP" \
  || fail "não foi possível descriptografar/extrair (chave errada?)"

WD=$(docker inspect -f '{{range .Mounts}}{{if eq .Source "'"$APP"'"}}{{.Destination}}{{end}}{{end}}' "$CONTAINER")
OUT=$(docker exec -w "$WD" "$CONTAINER" node -e "
const fs = require('fs'), path = require('path'), { DatabaseSync } = require('node:sqlite');
const base = fs.readdirSync('$TMP').find(d => d.startsWith('snap-'));
const dir = path.join('$TMP', base);
let bad = 0;
const files = ['master.sqlite', ...fs.readdirSync(path.join(dir, 'tenants')).map(f => 'tenants/' + f)];
for (const f of files) {
  const db = new DatabaseSync(path.join(dir, f), { readOnly: true });
  const ok = Object.values(db.prepare('PRAGMA integrity_check').get())[0];
  let extra = '';
  if (f.startsWith('tenants/')) extra = ' · OPs: ' + db.prepare('SELECT COUNT(*) n FROM ops').get().n + ' · lançamentos: ' + db.prepare('SELECT COUNT(*) n FROM op_daily_productions').get().n;
  console.log((ok === 'ok' ? 'OK  ' : 'FALHA ') + f + extra);
  if (ok !== 'ok') bad++;
  db.close();
}
process.exit(bad ? 1 : 0);
" 2>&1)
RESULT=$?
echo "$OUT" | grep -v -i experimental | grep -v trace-warnings
rm -rf "$TMP"
[ $RESULT -eq 0 ] && log "Restauração de $LATEST testada com sucesso" || fail "restauração com problema"
