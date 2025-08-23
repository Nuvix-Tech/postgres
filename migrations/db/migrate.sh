#!/bin/sh
set -eu

#######################################
# Used by both ami and docker builds to initialise database schema.
# Env vars:
#   POSTGRES_DB        defaults to postgres
#   POSTGRES_HOST      defaults to localhost
#   POSTGRES_PORT      defaults to 5432
#   POSTGRES_PASSWORD  defaults to ""
#   USE_DBMATE         defaults to ""
# Exit code:
#   0 if migration succeeds, non-zero on error.
#######################################

export PGDATABASE="${POSTGRES_DB:-postgres}"
export PGHOST="${POSTGRES_HOST:-localhost}"
export PGPORT="${POSTGRES_PORT:-5432}"
export PGPASSWORD="${POSTGRES_PASSWORD:-}"

connect="$PGPASSWORD@$PGHOST:$PGPORT/$PGDATABASE?sslmode=disable"

# If args are supplied, simply forward to dbmate
if [ "$#" -ne 0 ]; then
    export DATABASE_URL="${DATABASE_URL:-postgres://nuvix_admin:$connect}"
    exec dbmate "$@"
    exit 0
fi

db=$( cd -- "$( dirname -- "$0" )" > /dev/null 2>&1 && pwd )

if [ -z "${USE_DBMATE:-}" ]; then
    # Ensure postgres role exists
    psql -v ON_ERROR_STOP=1 --no-password --no-psqlrc -U nuvix_admin <<EOSQL
do \$\$
begin
  if not exists (select from pg_roles where rolname = 'postgres') then
    create role postgres superuser login password '$PGPASSWORD';
    alter database postgres owner to postgres;
  end if;
end \$\$
EOSQL

    # Promote nuvix_admin so it can own system objects
    psql -v ON_ERROR_STOP=1 --no-password --no-psqlrc -U postgres <<EOSQL
      ALTER USER nuvix_admin WITH SUPERUSER CREATEDB CREATEROLE REPLICATION BYPASSRLS PASSWORD '$PGPASSWORD';
EOSQL

    # Run init scripts as nuvix_admin (ownership will be correct)
    for sql in "$db"/init-scripts/*.sql; do
        echo "$0: running $sql"
        psql -v ON_ERROR_STOP=1 --no-password --no-psqlrc -U nuvix_admin -f "$sql"
    done

    # Run migrations as nuvix_admin
    for sql in "$db"/migrations/*.sql; do
        echo "$0: running $sql"
        psql -v ON_ERROR_STOP=1 --no-password --no-psqlrc -U nuvix_admin -f "$sql"
    done
else
    # Ensure postgres role exists
    psql -v ON_ERROR_STOP=1 --no-password --no-psqlrc -U nuvix_admin <<EOSQL
  create role postgres superuser login password '$PGPASSWORD';
  alter database postgres owner to postgres;
EOSQL

    # Promote nuvix_admin before migrations
    psql -v ON_ERROR_STOP=1 --no-password --no-psqlrc -U postgres <<EOSQL
      ALTER USER nuvix_admin WITH SUPERUSER CREATEDB CREATEROLE REPLICATION BYPASSRLS PASSWORD '$PGPASSWORD';
EOSQL

    # Run init scripts as nuvix_admin
    DBMATE_MIGRATIONS_DIR="$db/init-scripts" DATABASE_URL="postgres://nuvix_admin:$connect" dbmate --no-dump-schema migrate

    # Run migrations as nuvix_admin
    DBMATE_MIGRATIONS_DIR="$db/migrations" DATABASE_URL="postgres://nuvix_admin:$connect" dbmate --no-dump-schema migrate
fi

# Run any post migration script to update role passwords
postinit="/etc/postgresql.schema.sql"
if [ -e "$postinit" ]; then
    echo "$0: running $postinit"
    psql -v ON_ERROR_STOP=1 --no-password --no-psqlrc -U nuvix_admin -f "$postinit"
fi

# Reset stats after init
psql -v ON_ERROR_STOP=1 --no-password --no-psqlrc -U nuvix_admin -c 'SELECT extensions.pg_stat_statements_reset(); SELECT pg_stat_reset();' || true
