#!/bin/bash
# hand_answers.sh: answers worked out by hand from the language's reference (docs/reference/language.md), held
# against the database where only the database can give them: a share that expires, a caveat, `shared if`, a write
# checked before and after, a column rule, a masked column, `this` in a subquery. Each tests/hand/*.authz is a policy
# whose named tests hold the answers (`-- answer: name` says which paragraph of the page it is worked out from; the
# unit test HandAnswers checks every paragraph has a case, here or against the reference evaluator). Each is applied,
# as the tables' owner, to a database of its own made from tests/hand/schema.sql, and every check of its tests must
# pass: one `ok` a check. A check the database answers with an error rather than a refusal (`refused` is a refusal
# only: 42501, or a write that changes no row) ends with `-- error: ` and the error's words.
#   PGHOST=... PGUSER=authz_owner tests/hand_answers.sh
set -u
cd "$(dirname "$0")/.."
DB=authz_hand_answers
fails=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }
T=$(mktemp -d)

for f in tests/hand/*.authz; do
  name=$(basename "$f" .authz)
  dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
  PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f tests/hand/schema.sql >/dev/null || exit 1
  out=$(python3 cli/rowstile_cli.py --db "dbname=$DB" apply "$f" 2>&1) || { bad "$name: applying" "$out"; continue; }
  python3 tests/test_rows.py "dbname=$DB" > "$T/rows" 2>&1 || { bad "$name: its tests" "$(cat "$T/rows")"; continue; }
  # the checks the file writes (can/cannot, as ...), each with a row; the invariants' row aside (none here)
  want=$(grep -cE '^  (user|service|anyone|as) ' "$f")
  got=$(awk -F'\t' '$1 != "invariants"' "$T/rows" | wc -l)
  [ "$got" = "$want" ] || bad "$name: $want checks written, $got run" "$(cat "$T/rows")"
  while IFS=$'\t' read -r test line passed detail; do
    [ "$test" = invariants ] && continue
    n=${line##* }
    text=$(sed -n "${n}p" "$f" | sed 's/^ *//')
    # a line the database answers with an error, not a refusal, says so and its words: `-- error: words`
    words=$(echo "$text" | sed -n 's/.*-- error: //p')
    if [ -n "$words" ]; then
      case "$passed$detail" in "f"*"| error: $words") ok "$name, line $n: ${text%%  *}, an error: $words";;
        *) bad "$name, line $n: $text" "$detail";; esac
    elif [ "$passed" = t ]; then ok "$name, line $n: $text"; else bad "$name, line $n: $text" "$detail"; fi
  done < "$T/rows"
done

dropdb --if-exists "$DB" 2>/dev/null
rm -rf "$T"
if [ $fails -eq 0 ]; then echo "hand answers: all passed"; else echo "hand answers: $fails failed"; exit 1; fi
