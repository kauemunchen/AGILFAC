#!/bin/sh
# Deploy automático do AgilFac (roda no VPS via cron a cada minuto).
# Se houver commit novo em origin/main: backup dos bancos -> atualiza código ->
# valida sintaxe -> reinicia -> testa saúde. Se algo falhar, volta a versão anterior.
set -u

APP=/opt/agilfac
CONTAINER=agilfac-agilfac-1
HEALTH_URL=http://127.0.0.1:8090/

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*"; }

cd "$APP" || exit 1

# Evita duas execuções ao mesmo tempo
exec 9>/tmp/agilfac-deploy.lock
flock -n 9 || exit 0

git fetch -q origin main || { log "ERRO: git fetch falhou"; exit 1; }
OLD=$(git rev-parse HEAD)
NEW=$(git rev-parse origin/main)
[ "$OLD" = "$NEW" ] && exit 0

log "Deploy ${OLD%${OLD#???????}} -> ${NEW%${NEW#???????}}"

# Não sobrescreve alterações feitas direto no servidor
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  log "ABORTADO: há alterações locais não commitadas em $APP (git status)"
  exit 1
fi

# Backup dos bancos antes de qualquer mudança
mkdir -p "$APP/backups"
tar -czf "$APP/backups/pre-deploy-$(date +%Y%m%d-%H%M%S).tar.gz" -C "$APP" data \
  || { log "ABORTADO: backup falhou"; exit 1; }
ls -1t "$APP"/backups/pre-deploy-*.tar.gz 2>/dev/null | tail -n +31 | xargs -r rm -f

rollback() {
  log "FALHA: $1 — voltando para ${OLD%${OLD#???????}}"
  git reset -q --hard "$OLD"
  docker restart "$CONTAINER" >/dev/null
  exit 1
}

# Pasta do projeto dentro do container
WD=$(docker inspect -f '{{range .Mounts}}{{if eq .Source "'"$APP"'"}}{{.Destination}}{{end}}{{end}}' "$CONTAINER")
[ -n "$WD" ] || { log "ABORTADO: não achei o volume $APP no container"; exit 1; }

git merge -q --ff-only origin/main || { log "ABORTADO: merge não é fast-forward"; exit 1; }

# Dependências mudaram?
if git diff --name-only "$OLD" "$NEW" | grep -q '^package-lock.json$'; then
  log "package-lock mudou: instalando dependências"
  docker exec -w "$WD" "$CONTAINER" npm ci --omit=dev >/dev/null 2>&1 || rollback "npm ci"
fi

# Sintaxe de todos os .js alterados
for f in $(git diff --name-only "$OLD" "$NEW" -- '*.js'); do
  [ -f "$f" ] || continue
  docker exec -w "$WD" "$CONTAINER" node --check "$f" || rollback "erro de sintaxe em $f"
done

docker restart "$CONTAINER" >/dev/null || rollback "docker restart"

# Saúde: até 30 s para responder sem erro 5xx
i=0
while [ $i -lt 15 ]; do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' "$HEALTH_URL" || echo 000)
  case "$CODE" in 2*|3*|4*) log "OK: no ar (HTTP $CODE)"; exit 0 ;; esac
  i=$((i + 1)); sleep 2
done
rollback "sistema não respondeu (HTTP $CODE)"
