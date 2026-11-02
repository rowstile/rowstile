#!/usr/bin/env bash
# The scale benchmark's dev data (400k files, 20k folders, 20 levels, 1000 users, 100 teams) with the docs policy
# applied and the bench's shares, for measure.sh. From core/
set -u
DB=${DB:-authz_sync_bench}
PSQL() { PGOPTIONS="-c client_min_messages=warning" psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
now() { date +%s.%N; }
since() { python3 -c "print(f'{($(now) - $1):.2f}')"; }
psql -X -q -d postgres -c "DO \$r\$ BEGIN CREATE ROLE authz_sync_engine; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END \$r\$;" >/dev/null
dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null || exit 1
psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -v files=400000 -v folders=20000 -v levels=20 -v users=1000 -v teams=100 -f bench/load.sql >/dev/null || exit 1
python3 cli/rowstile_cli.py --db "dbname=$DB" apply example/docs.authz >/dev/null 2>&1 || { echo "apply failed"; exit 1; }
psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -v files=400000 -v folders=20000 -v users=1000 -v teams=100 -f bench/shares.sql >/dev/null || exit 1
PSQL -c "VACUUM ANALYZE" >/dev/null 2>&1
echo "loaded"
