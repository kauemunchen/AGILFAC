# README-OPERACAO-AGILFAC

Guia rápido de operação do AgilFac na VPS.

## Domínio principal
```bash
https://app.agilfac.com.br
```

## Domínio secundário
```bash
https://app.agilfac.tech
```

## Pasta principal do projeto
```bash
/opt/agilfac
```

## Docker compose
```bash
/docker/agilfac/docker-compose.yml
```

## Container principal
```bash
agilfac-agilfac-1
```

## Arquivos principais
```bash
/opt/agilfac/server.js
/opt/agilfac/package.json
/opt/agilfac/package-lock.json
/opt/agilfac/database/schema.sql
/opt/agilfac/database/master-schema.sql
/opt/agilfac/public/styles.css
```

## Bancos de dados
### Banco mestre
```bash
/opt/agilfac/data/master.sqlite
```

### Bancos por empresa
```bash
/opt/agilfac/data/tenants/mais-textil.sqlite
/opt/agilfac/data/tenants/douglas-confeccoes.sqlite
/opt/agilfac/data/tenants/mais-joinville.sqlite
```

## Comandos principais
### Entrar no projeto
```bash
cd /opt/agilfac
```

### Ver arquivos
```bash
ls -la /opt/agilfac
```

### Validar sintaxe do backend
```bash
cd /opt/agilfac
node --check server.js
```

### Ver status dos containers
```bash
docker ps
```

### Ver só o AgilFac
```bash
docker ps | grep agilfac
```

### Ver logs do AgilFac
```bash
docker logs --tail 100 agilfac-agilfac-1
```

### Acompanhar logs em tempo real
```bash
docker logs -f agilfac-agilfac-1
```

### Reiniciar o AgilFac
```bash
docker restart agilfac-agilfac-1
```

### Reiniciar pelo compose
```bash
cd /docker/agilfac
docker compose restart
```

### Derrubar e subir novamente
```bash
cd /docker/agilfac
docker compose down
docker compose up -d
```

## Testes rápidos
### Teste local
```bash
curl -I http://127.0.0.1:8090/
```

### Teste domínio principal
```bash
curl -Ik https://app.agilfac.com.br/
```

### Teste domínio secundário
```bash
curl -Ik https://app.agilfac.tech/
```

## Edição de arquivos
### Backend principal
```bash
nano /opt/agilfac/server.js
```

### Schema principal
```bash
nano /opt/agilfac/database/schema.sql
```

### Compose
```bash
nano /docker/agilfac/docker-compose.yml
```

## SQLite
### Abrir banco mestre
```bash
sqlite3 /opt/agilfac/data/master.sqlite
```

### Abrir banco Mais Têxtil
```bash
sqlite3 /opt/agilfac/data/tenants/mais-textil.sqlite
```

### Abrir banco Douglas
```bash
sqlite3 /opt/agilfac/data/tenants/douglas-confeccoes.sqlite
```

### Comandos úteis no sqlite
```sql
.tables
.schema employees
.quit
```

## Backups
### Backup completo da pasta do sistema
```bash
tar -czf /opt/agilfac-backup-$(date -u +%Y-%m-%d-%H%MUTC).tar.gz -C /opt agilfac
```

### Backup só dos bancos
```bash
tar -czf /opt/agilfac-bancos-$(date -u +%Y-%m-%d-%H%MUTC).tar.gz -C /opt/agilfac/data .
```

## Proxy / domínio
### Ver compose atual
```bash
cat /docker/agilfac/docker-compose.yml
```

### Validar compose
```bash
cd /docker/agilfac
docker compose config
```

### Reiniciar Traefik
```bash
docker restart traefik-traefik-1
```

### Logs do Traefik
```bash
docker logs --tail 100 traefik-traefik-1
```

## Verificar mount do container
```bash
docker inspect agilfac-agilfac-1 --format '{{json .Mounts}}'
```

## Acesso funcional atual (Mais Têxtil)
- empresa: `mais-textil`
- usuário: `admin`

> Recomendado trocar a senha depois.

## Fluxo recomendado de manutenção
1. Editar arquivo em `/opt/agilfac`
2. Validar com `node --check server.js`
3. Reiniciar com `docker restart agilfac-agilfac-1`
4. Conferir com `docker logs --tail 100 agilfac-agilfac-1`
5. Testar com `curl -Ik https://app.agilfac.com.br/`
