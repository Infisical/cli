#!/bin/bash
set -e

# Start SQL Server in the background
/opt/mssql/bin/sqlservr &
MSSQL_PID=$!

# Wait for SQL Server to be ready
echo "Waiting for SQL Server to start..."
for i in $(seq 1 60); do
    if /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$MSSQL_SA_PASSWORD" -C -Q "SELECT 1" &>/dev/null; then
        echo "SQL Server is ready."
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "Timed out waiting for SQL Server to start."
        exit 1
    fi
    sleep 1
done

# Create database and user
DB="${MSSQL_DATABASE:-infisical}"
USR="${MSSQL_USER:-infisical}"
PW="${MSSQL_PASSWORD:-Infisical@123}"

/opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$MSSQL_SA_PASSWORD" -C -Q "
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = N'$DB')
    CREATE DATABASE [$DB];
"

/opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$MSSQL_SA_PASSWORD" -C -d "$DB" -Q "
-- CHECK_POLICY = OFF: the server policy rejects passwords that contain the
-- username ('Infisical@123' contains 'infisical'). All other policy rules are
-- still satisfied; we just opt this one login out so the dev creds work.
IF NOT EXISTS (SELECT name FROM sys.server_principals WHERE name = N'$USR')
    CREATE LOGIN [$USR] WITH PASSWORD = N'$PW', DEFAULT_DATABASE = [$DB], CHECK_POLICY = OFF;

IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name = N'$USR')
    CREATE USER [$USR] FOR LOGIN [$USR];

ALTER ROLE db_owner ADD MEMBER [$USR];
"

# Run init scripts only on first boot. The pam_mssqldata volume persists, so
# without this guard `make down && make up` would replay seed.sql against
# already-populated tables and spam errors. -b makes sqlcmd return non-zero on
# SQL errors so set -e actually catches them.
SENTINEL=/var/opt/mssql/.seeded
if [ ! -f "$SENTINEL" ]; then
    for f in /docker-entrypoint-initdb.d/*.sql; do
        if [ -f "$f" ]; then
            echo "Running $f ..."
            /opt/mssql-tools18/bin/sqlcmd -b -S localhost -U sa -P "$MSSQL_SA_PASSWORD" -C -d "$DB" -i "$f"
        fi
    done
    touch "$SENTINEL"
    echo "Initialization complete."
else
    echo "Init scripts already applied (sentinel $SENTINEL present); skipping."
fi

# Keep SQL Server in the foreground
wait $MSSQL_PID
