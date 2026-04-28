# PAM dev stack

When you're working on PAM you need a handful of databases and SSH servers to point it at. This brings them up locally and registers them in your Infisical so you can skip the manual wiring.

## Quickstart

```bash
cd dev/pam
cp .env.example .env    # edit .env and fill in the values
make up
```

`make up` brings up the services you flagged in `.env`, prints the table below, and asks if it should register them in Infisical.

```
PAM dev stack — connection details:

resource              host       port   user       password       extras
postgres              127.0.0.1  55432  infisical  Infisical@123  db=infisical
redis                 127.0.0.1  55479  infisical  Infisical@123

Register in Infisical now? [y/N] y

Prefix: local01-2026-04-25
Registering resources in Infisical ...
  ok: local01-2026-04-25-postgres + local01-2026-04-25-postgres-account
  ok: local01-2026-04-25-redis + local01-2026-04-25-redis-account

Access snippets:
postgres (local01-2026-04-25-postgres / local01-2026-04-25-postgres-account)
  CLI:  go run main.go pam db access --resource local01-2026-04-25-postgres --account local01-2026-04-25-postgres-account --project-id <id> --duration 1h --domain http://localhost:8080
  Web:  http://localhost:8080/organizations/<org>/projects/pam/<project>/resources/postgres/<rid>/accounts/<aid>/access
```

## `.env`

```env
INFISICAL_TOKEN=                 # browser cookie 'jid' from the Infisical UI; machine-identity tokens don't work
INFISICAL_DOMAIN=http://localhost:8080
INFISICAL_PROJECT_ID=
INFISICAL_GATEWAY_ID=            # required; grab it from Infisical UI > Access Control > Gateways
INFISICAL_ORG_ID=                # optional, only used to print web-access URLs

RESOURCE_PREFIX=local01          # bump if names collide (e.g. local02)

ENABLE_POSTGRES=true
ENABLE_MYSQL=false
ENABLE_MSSQL=false
ENABLE_MONGODB=false
ENABLE_REDIS=false
ENABLE_REDIS_NOAUTH=false
ENABLE_SSH_PASSWORD=false
ENABLE_SSH_KEY=false
```

## Make targets

```
make up      # build + start enabled services + offer to register
make setup   # rerun the Infisical registration only
make info    # reprint the connection table
make down    # stop containers, keep data
make clean   # stop + wipe volumes + local images
```
