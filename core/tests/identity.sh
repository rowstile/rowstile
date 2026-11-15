#!/bin/bash
# identity.sh: scopes, API keys, JWT login, view-as and group sync.
#   PGHOST=... PGPORT=... PGUSER=authz_owner tests/identity.sh [database]
set -u
cd "$(dirname "$0")/.."
DB=${1:-authz_identity}
T=$(mktemp -d)
. tests/races.sh
# whatever way the suite ends: the sessions it left running, its databases, its files
cleanup() { stop_sessions; for d in "$DB" "${DB}_cx"; do dropdb --force --if-exists "$d" 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT
dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
fails=0
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
check() {   # $1 label, $2 expected, $3 SQL (run as app_user)
  got=$(PSQL -c "SET ROLE app_user;" -c "$3" 2>&1 | tail -n 1)
  if [ "$got" = "$2" ]; then echo "ok    $1"; else echo "FAIL  $1: expected '$2', got '$got'"; fails=$((fails + 1)); fi
}
state() { psql -X -q -At -d "$DB" -c "SET ROLE app_user;" "$@" 2>&1 | tail -n 1; }
. tests/words.sh
expect_code() {  # $1 label, $2 expected "SQLSTATE: the message's words" (or ok), rest: -c statements
  local label=$1 want=$2; shift 2
  got=$(psql -X -q -At -d "$DB" -v VERBOSITY=verbose -c "SET ROLE app_user;" "$@" 2>&1 | grep '^ERROR:  ' | tail -n 1)
  got=${got#ERROR:  }; got=${got:-ok}
  if agrees "$label" "$want" "$got"; then echo "ok    $label"; else echo "FAIL  $label: expected $want, got $got"; fails=$((fails + 1)); fi
}
# $1 label, $2 the sign-in, $3 a call that fails after it switched who is signed in, $4 its error ("SQLSTATE: words"):
# caught at a savepoint, the transaction goes on signed in exactly as before (Postgres undoes what the call set)
SETTINGS="concat_ws('|', current_setting('authz.user_id', true), current_setting('authz.principal_type', true),
  current_setting('authz.scopes', true), current_setting('authz.acting_user', true), current_setting('authz.session', true))"
caught() {
  local out err
  out=$(psql -X -q -At -d "$DB" -v VERBOSITY=verbose 2>&1 <<SQL
BEGIN;
$2;
SELECT $SETTINGS AS before \gset
SAVEPOINT s;
$3;
ROLLBACK TO SAVEPOINT s;
SELECT ($SETTINGS) = :'before' AND authz.uid() IS NOT NULL;
COMMIT;
SQL
)
  err=$(printf '%s\n' "$out" | grep '^ERROR:  ' | head -n 1)
  if agrees "$1" "$4" "${err#ERROR:  }" && [ "$(printf '%s\n' "$out" | tail -n 1)" = t ]; then echo "ok    $1"
  else echo "FAIL  $1: $out"; fails=$((fails + 1)); fi
}

# the docs app, with a scope that may view as someone (a support desk's key)
sed '/^scope files = /a scope support = user.impersonate' example/docs.authz > $T/identity.authz
grep -q '^scope support = ' $T/identity.authz || { echo "FAIL  the support scope added to the docs app"; exit 1; }
python3 compile_policy.py $T/identity.authz > $T/identity.sql || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null &&
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f $T/identity.sql >/dev/null || exit 1
PSQL -c "SET ROLE app_user; SET authz.user_id = 5; SELECT authz.share('folder', 1, 'viewer', 'org', 1, 'member')" >/dev/null

echo "-- scopes and API keys"
READ=$(state -c "SET authz.user_id = 1" -c "SELECT authz.create_api_key('laptop', 'read')")
FILES=$(state -c "SET authz.user_id = 1" -c "SELECT authz.create_api_key('script', 'files')")
case "$READ" in ak_*) echo "ok    alice creates a read-only key (shown once)";; *) echo "FAIL  key: $READ"; fails=$((fails + 1));; esac
# the key itself is nowhere in the table: its SHA-256 hash, and its first ten characters to tell keys apart
check "only the key's hash is kept, and its first ten characters" "true|true|true" \
  "RESET ROLE; SELECT (hash = encode(sha256(convert_to('$READ', 'UTF8')), 'hex')) || '|' || (prefix = left('$READ', 10)) || '|'
     || (position('$READ' in k::text) = 0) FROM authz.api_keys k WHERE name = 'laptop';"
check "the key signs in as alice" "1" "BEGIN; SELECT authz.login_key('$READ'); SELECT authz.uid(); COMMIT;"
check "read-only key: may view file 11, not edit it" "true|false" \
  "BEGIN; SELECT authz.login_key('$READ'); SELECT authz.can('file', 11, 'view') || '|' || authz.can('file', 11, 'edit'); COMMIT;"
# what a scoped key may still find out about its own user (docs/threat-model.md): explain's first line is the key's
# answer, and the parts below are walked with the user's full rights, without naming the scope as the reason
check "a read-only key's explain of edit: no for the key, then the parts its user holds" \
  "no   user 1 does not hold edit on file 11|true" \
  "BEGIN; SELECT authz.login_key('$READ'); SELECT (array_agg(e ORDER BY n))[1] || '|' || bool_or(btrim(e) = 'yes  folder.edit') FROM authz.explain('file', 11, 'edit') WITH ORDINALITY AS x(e, n); COMMIT;"
# (its scope names the command select, not a permission: asked as one, it is outside the scope too, and false)
check "... and a permission named as the command it may run is not in its scope" "false|0" \
  "BEGIN; SELECT authz.login_key('$READ'); SELECT authz.can('file', 11, 'select') || '|' || (SELECT count(*) FROM authz.list('file', 'select')); COMMIT;"
check "read-only key: SELECT works" "3" "BEGIN; SELECT authz.login_key('$READ'); SELECT count(*) FROM app.files; COMMIT;"
check "read-only key: UPDATE changes nothing" "0" \
  "BEGIN; SELECT authz.login_key('$READ'); WITH u AS (UPDATE app.files SET body = 'x' WHERE id = 11 RETURNING 1) SELECT count(*) FROM u; ROLLBACK;"
expect_code "read-only key: cannot share" "42501: this session is read-only (viewing as someone else, or a read-only token)" -c "BEGIN" -c "SELECT authz.login_key('$READ')" \
  -c "SELECT authz.share('file', 11, 'viewer', 'user', 4)"
got=$(psql -X -q -At -d "$DB" -v VERBOSITY=verbose -c "SET ROLE app_user" -c "BEGIN" -c "SELECT authz.login_key('$READ')" \
  -c "INSERT INTO app.files (folder_id, owner_id, name) VALUES (6, 1, 'x')" 2>&1)
case "$got" in *"no   the sign-in's scopes do not allow insert on app.files"*) echo "ok    read-only key: a refused insert says the scopes allow no insert";;
  *) echo "FAIL  read-only key, an insert: $got"; fails=$((fails + 1));; esac
expect_code "read-only key: cannot approve a request" "42501: this session is read-only (viewing as someone else, or a read-only token)" -c "BEGIN" -c "SELECT authz.login_key('$READ')" \
  -c "SELECT authz.decide_request(1, true)"
expect_code "read-only key: cannot make a custom role (refused before anything else is asked)" "42501: this session is read-only (viewing as someone else, or a read-only token)" -c "BEGIN" -c "SELECT authz.login_key('$READ')" \
  -c "SELECT authz.create_role('org', 1, 'folder', 'reader', ARRAY['view'])"
expect_code "a read-only session cannot mint a broader key" "42501: this session is read-only (viewing as someone else, or a read-only token)" -c "BEGIN" -c "SELECT authz.login_key('$READ')" \
  -c "SELECT authz.create_api_key('sneaky', 'files')"
expect_code "a session limited to a scope cannot make a key with another" "42501: a key cannot have more scopes than the session creating it" \
  -c "BEGIN" -c "SELECT authz.login_key('$FILES')" -c "SELECT authz.create_api_key('wider', 'read')"
expect_code "... nor one with every scope (none named)" "42501: a key cannot have more scopes than the session creating it" \
  -c "BEGIN" -c "SELECT authz.login_key('$FILES')" -c "SELECT authz.create_api_key('wider')"
# ... nor revoke one: a scope that holds a write command is no say over its user's other keys. (alice makes a key
# with every scope first, in the same transaction; her keys are named by authz.list_api_keys, which the session may ask)
expect_code "a session limited to a scope cannot revoke its user's key with every scope" "42501: a session limited by scopes cannot revoke a key with more scopes than its own" \
  -c "BEGIN" -c "SET LOCAL authz.user_id = 1" -c "SELECT authz.create_api_key('everything') IS NOT NULL" -c "SELECT authz.login_key('$FILES')" \
  -c "SELECT authz.revoke_api_key((SELECT id FROM authz.list_api_keys() WHERE name = 'everything'))"
expect_code "... nor one with another scope" "42501: a session limited by scopes cannot revoke a key with more scopes than its own" \
  -c "BEGIN" -c "SELECT authz.login_key('$FILES')" -c "SELECT authz.revoke_api_key((SELECT id FROM authz.list_api_keys() WHERE name = 'laptop'))"
check "... it revokes a key with its own scopes (itself), and the other is as it was" "true|false" \
  "BEGIN; SELECT authz.login_key('$FILES'); SELECT authz.revoke_api_key((SELECT id FROM authz.list_api_keys() WHERE name = 'script'));
   SELECT (SELECT revoked_at IS NOT NULL FROM authz.list_api_keys() WHERE name = 'script') || '|' || (SELECT revoked_at IS NOT NULL FROM authz.list_api_keys() WHERE name = 'laptop'); ROLLBACK;"
check "... and a session without scopes revokes any of its user's keys" "t" \
  "BEGIN; SET LOCAL authz.user_id = 1; SELECT authz.revoke_api_key((SELECT id FROM authz.list_api_keys() WHERE name = 'script'));
   SELECT revoked_at IS NOT NULL FROM authz.list_api_keys() WHERE name = 'script'; ROLLBACK;"
expect_code "a scope the policy doesn't have is a mistake, not a key" "P0001: no scope boat in the policy" \
  -c "SET authz.user_id = 1" -c "SELECT authz.create_api_key('k', 'read, boat')"
expect_code "a key for another user: users' keys are their own (the policy gives user no manage_keys)" \
  "P0001: the policy gives user no manage_keys permission, so nobody manages its keys" \
  -c "SET authz.user_id = 1" -c "SELECT authz.create_api_key('k', 'read', NULL, 'user', '3')"
check "blank pieces of a list of scopes are left out" "read" \
  "SET authz.user_id = 1; BEGIN; SELECT authz.create_api_key('blank', 'read, ,'); SELECT scopes FROM authz.list_api_keys() WHERE name = 'blank'; ROLLBACK;"
expect_code "nobody signed in makes no key" "42501: sign in to create an API key" -c "SELECT authz.create_api_key('k', 'read')"
said=$(psql -X -q -At -d "$DB" -c "SET ROLE app_user;" -c "SELECT authz.create_api_key('k', 'read')" 2>&1 | grep '^HINT:  ')
[ "$said" = "HINT:  rowstile help AZ714" ] && echo "ok    ... and its code is sign in first (AZ714, a 401), not a refusal" ||
  { echo "FAIL  sign in first's code: $said"; fails=$((fails + 1)); }
check "files key: may edit files, and update them" "updated" \
  "BEGIN; SELECT authz.login_key('$FILES'); SELECT authz.can('file', 11, 'edit'); UPDATE app.files SET body = 'y' WHERE id = 11 RETURNING 'updated'; ROLLBACK;"
check "files key: sees no folders (not in its scope)" "0|false" \
  "BEGIN; SELECT authz.login_key('$FILES'); SELECT (SELECT count(*) FROM app.folders) || '|' || authz.can('folder', 3, 'view'); COMMIT;"
# explaining someone else's access answers about them as authz.who does: with their full rights, for what the
# caller's scopes name (asked here in the owner's session, which may inspect anything)
check "explaining bob's access from a scoped session walks with his full rights, as who does" "yes  folder is folder 4, which has edit" \
  "RESET ROLE; SET authz.user_id = 1; SET authz.scopes = 'files'; SELECT btrim(e) FROM authz.explain('file', 11, 'edit', '2') e WHERE e LIKE '%folder is%' LIMIT 1;"
expect_code "... and refuses a permission the scopes don't name, as who does" "42501: you cannot inspect access to file 11" \
  -c "RESET ROLE" -c "SET authz.user_id = 1" -c "SET authz.scopes = 'read'" -c "SELECT authz.explain('file', 11, 'edit', '2')"
check "... and leaves the session's scopes as they were" "files|1" \
  "RESET ROLE; SET authz.user_id = 1; SET authz.scopes = 'files'; SELECT count(*) FROM authz.explain('file', 11, 'edit', '2'); SELECT current_setting('authz.scopes') || '|' || current_setting('authz.user_id');"
check "alice lists her keys" "2" "SET authz.user_id = 1; SELECT count(*) FROM authz.list_api_keys();"
check "a key signs in to a read-only transaction (a replica, a GET)" "1"   "BEGIN READ ONLY; SELECT authz.login_key('$FILES'); SELECT authz.uid(); COMMIT;"
PSQL -c "UPDATE authz.api_keys SET last_used_at = NULL" >/dev/null
# one request holds the key's row (it signed in first and is still running): another with the key doesn't wait
race
PGAPPNAME=authz_identity_a PSQL -c "SET ROLE app_user" -c "BEGIN" -c "SELECT authz.login_key('$FILES')" -c "$HOLD" -c "COMMIT" >/dev/null &
held authz_identity_a
check "... and requests with one key don't wait for each other" "1"   "SET statement_timeout = '1500ms'; BEGIN; SELECT authz.login_key('$FILES'); SELECT authz.uid(); COMMIT;"
go; wait
check "... last_used_at is kept, to the minute" "t"   "RESET ROLE; SELECT last_used_at > now() - interval '1 minute' FROM authz.api_keys WHERE name = 'script';"
check "... not written again until a minute has passed" "t" \
  "RESET ROLE; BEGIN; UPDATE authz.api_keys SET last_used_at = now() - interval '1 minute' WHERE name = 'script';
   SET LOCAL ROLE app_user; SELECT authz.login_key('$FILES'); RESET ROLE;
   SELECT last_used_at = now() - interval '1 minute' FROM authz.api_keys WHERE name = 'script'; ROLLBACK;"
KEYID=$(state -c "SET authz.user_id = 1" -c "SELECT id FROM authz.list_api_keys() WHERE name = 'laptop'")
expect_code "bob cannot revoke alice's key" "P0001: no API key $KEYID of yours" -c "SET authz.user_id = 2" -c "SELECT authz.revoke_api_key($KEYID)"
PSQL -c "SET ROLE app_user; SET authz.user_id = 1; SELECT authz.revoke_api_key($KEYID)" >/dev/null
expect_code "a revoked key no longer signs in" "28000: invalid API key" -c "BEGIN" -c "SELECT authz.login_key('$READ')"
expect_code "... nor is revoked again" "P0001: no API key $KEYID of yours" -c "SET authz.user_id = 1" -c "SELECT authz.revoke_api_key($KEYID)"
check "the audit trail has the keys made and the one revoked, with whose they are" \
  "create_api_key 1 laptop|create_api_key 1 script|revoke_api_key 1 $KEYID" \
  "RESET ROLE; SELECT string_agg(action || ' ' || object_id || ' ' || coalesce(detail ->> 'name', detail ->> 'key'), '|'
                                 ORDER BY action, coalesce(detail ->> 'name', detail ->> 'key'))
   FROM authz.audit WHERE action LIKE '%api_key';"
expect_code "a made-up key does not either" "28000: invalid API key" -c "BEGIN" -c "SELECT authz.login_key('ak_nope')"
SHORT=$(state -c "SET authz.user_id = 1" -c "SELECT authz.create_api_key('for an hour', 'read', now() + interval '1 hour')")
check "a key with an end signs in until then" "1" "BEGIN; SELECT authz.login_key('$SHORT'); SELECT authz.uid(); COMMIT;"
PSQL -c "UPDATE authz.api_keys SET expires_at = now() - interval '1 hour' WHERE name = 'for an hour'" >/dev/null
expect_code "... and no longer after it" "28000: invalid API key" -c "BEGIN" -c "SELECT authz.login_key('$SHORT')"
expect_code "... nor at the very moment it ends" "28000: invalid API key" -c "RESET ROLE" -c "BEGIN" \
  -c "UPDATE authz.api_keys SET expires_at = now() WHERE name = 'for an hour'" -c "SET LOCAL ROLE app_user" \
  -c "SELECT authz.login_key('$SHORT')"

echo "-- JWT (HS256)"
expect_code "no secret and no keys, no JWT login" "28000: JWT login is not configured (authz.settings jwt_secret, or keys stored with authz.set_jwks)" -c "BEGIN" -c "SELECT authz.login_jwt('a.b.c')"
PSQL -c "INSERT INTO authz.settings VALUES ('jwt_secret', 's3cret-for-tests'), ('jwt_issuer', 'https://id.example')" >/dev/null
jwt() { python3 - "$@" <<'PY'
import base64, hashlib, hmac, json, sys, time
secret, sub, ttl, extra = sys.argv[1], sys.argv[2], int(sys.argv[3]), json.loads(sys.argv[4])
b = lambda d: base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()
head = extra.pop("_header", {"alg": "HS256", "typ": "JWT"})
body = dict({"sub": sub, "exp": int(time.time()) + ttl, "iss": "https://id.example"}, **extra)
msg = b(head) + "." + b(body)
sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
print(msg + "." + sig)
PY
}
T_OK=$(jwt s3cret-for-tests 2 300 '{"scope": "read"}')
T_BADSIG=$(jwt wrong-secret 2 300 '{}')
T_EXPIRED=$(jwt s3cret-for-tests 2 -10 '{}')
T_ISS=$(jwt s3cret-for-tests 2 300 '{"iss": "https://evil.example"}')
T_NONE=$(jwt s3cret-for-tests 2 300 '{"_header": {"alg": "none"}}')
T_NOEXP=$(python3 - <<'PY'
import base64, hashlib, hmac, json
b = lambda d: base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()
msg = b({"alg": "HS256", "typ": "JWT"}) + "." + b({"sub": "2", "iss": "https://id.example"})
print(msg + "." + base64.urlsafe_b64encode(hmac.new(b"s3cret-for-tests", msg.encode(), hashlib.sha256).digest()).rstrip(b"=").decode())
PY
)
check "a valid token signs in as bob, with its scope" "2|read" \
  "BEGIN; SELECT authz.login_jwt('$T_OK'); SELECT authz.uid() || '|' || current_setting('authz.scopes'); COMMIT;"
check "... a scope the policy doesn't have is left out of it" "read" \
  "BEGIN; SELECT authz.login_jwt('$(jwt s3cret-for-tests 2 300 '{"scope": "boat read"}')'); SELECT current_setting('authz.scopes'); COMMIT;"
check "... and turns JIT off for the transaction" "off" \
  "BEGIN; SET LOCAL jit = on; SELECT authz.login_jwt('$T_OK'); SELECT current_setting('jit'); COMMIT;"
expect_code "wrong signature" "28000: invalid token" -c "BEGIN" -c "SELECT authz.login_jwt('$T_BADSIG')"
expect_code "expired" "28000: token expired or not yet valid" -c "BEGIN" -c "SELECT authz.login_jwt('$T_EXPIRED')"
expect_code "another issuer" "28000: token from another issuer" -c "BEGIN" -c "SELECT authz.login_jwt('$T_ISS')"
expect_code "a token that names no issuer, once one is asked" "28000: token from another issuer" -c "BEGIN" \
  -c "SELECT authz.login_jwt('$(jwt s3cret-for-tests 2 300 '{"iss": null}')')"
expect_code "alg none" "28000: invalid token" -c "BEGIN" -c "SELECT authz.login_jwt('$T_NONE')"
expect_code "a token not in three parts" "28000: invalid token" -c "BEGIN" -c "SELECT authz.login_jwt('$(echo "$T_OK" | cut -d. -f1,2)')"
expect_code "no expiry" "28000: token expired or not yet valid" -c "BEGIN" -c "SELECT authz.login_jwt('$T_NOEXP')"
# nbf is optional; the hours keep these far from a clock that steps a few seconds
expect_code "not valid yet (nbf in an hour)" "28000: token expired or not yet valid" -c "BEGIN" \
  -c "SELECT authz.login_jwt('$(jwt s3cret-for-tests 2 7200 "{\"nbf\": $(( $(date +%s) + 3600 ))}")')"
expect_code "an nbf that isn't a number" "28000: token expired or not yet valid" -c "BEGIN" -c "SELECT authz.login_jwt('$(jwt s3cret-for-tests 2 300 '{"nbf": "soon"}')')"
# an exp that is there but no number: a string of digits would never expire if read as one, and other words would
# fail a cast: refused as the expiry, both
expect_code "an exp that is a string of digits" "28000: token expired or not yet valid" -c "BEGIN" -c "SELECT authz.login_jwt('$(jwt s3cret-for-tests 2 300 '{"exp": "9999999999"}')')"
expect_code "an exp that is words" "28000: token expired or not yet valid" -c "BEGIN" -c "SELECT authz.login_jwt('$(jwt s3cret-for-tests 2 300 '{"exp": "soon"}')')"
check "valid since an hour (nbf in the past)" "2" \
  "BEGIN; SELECT authz.login_jwt('$(jwt s3cret-for-tests 2 300 "{\"nbf\": $(( $(date +%s) - 3600 ))}")'); COMMIT;"
expect_code "a valid token for a user the database doesn't have" "28000: the token names no active user" -c "BEGIN" \
  -c "SELECT authz.login_jwt('$(jwt s3cret-for-tests 999 300 '{}')')"
caught "... caught at a savepoint: who was signed in before still is" "SELECT authz.act_as('user', '1')" \
  "SELECT authz.login_jwt('$(jwt s3cret-for-tests 999 300 '{}')')" "28000: the token names no active user"
# an audience, once the setting names one: a string or a list holding it
PSQL -c "INSERT INTO authz.settings VALUES ('jwt_audience', 'docs-api')" >/dev/null
expect_code "a token for no audience, once one is asked" "28000: token for another audience" -c "BEGIN" -c "SELECT authz.login_jwt('$T_OK')"
expect_code "a token for another audience" "28000: token for another audience" -c "BEGIN" -c "SELECT authz.login_jwt('$(jwt s3cret-for-tests 2 300 '{"aud": "other-api"}')')"
check "a token for this audience" "2" "BEGIN; SELECT authz.login_jwt('$(jwt s3cret-for-tests 2 300 '{"aud": "docs-api"}')'); COMMIT;"
check "a JWT login lasts its transaction: the session's acting user is back after it" "8" \
  "SET authz.acting_user = '8'; BEGIN; SELECT authz.login_jwt('$(jwt s3cret-for-tests 2 300 '{"aud": "docs-api"}')'); COMMIT;
   SELECT current_setting('authz.acting_user');"
check "... or for a list that holds it" "2" "BEGIN; SELECT authz.login_jwt('$(jwt s3cret-for-tests 2 300 '{"aud": ["other-api", "docs-api"]}')'); COMMIT;"
expect_code "... but not for a list that doesn't" "28000: token for another audience" -c "BEGIN" -c "SELECT authz.login_jwt('$(jwt s3cret-for-tests 2 300 '{"aud": ["other-api"]}')')"
PSQL -c "DELETE FROM authz.settings WHERE key = 'jwt_audience'" >/dev/null
# a secret as long as SHA-256's block (64 bytes) is used as it is; a longer one is hashed first (HMAC, RFC 2104)
for n in 64 65; do
  secret=$(printf 'k%.0s' $(seq "$n"))
  check "a secret of $n bytes signs as an HMAC library signs with it" "2" \
    "RESET ROLE; BEGIN; UPDATE authz.settings SET value = '$secret' WHERE key = 'jwt_secret'; SET LOCAL ROLE app_user;
     SELECT authz.login_jwt('$(jwt "$secret" 2 300 '{}')'); ROLLBACK;"
done
# a token made in the transaction that signs in with it, so that its exp or nbf is that transaction's now()
b64url() { echo "rtrim(translate(encode($1, 'base64'), E'+/\\n', '-_'), '=')"; }   # $1: bytea, in SQL
at_now() {  # $1: the claims beside sub and iss, as jsonb_build_object's arguments, with now_s the time now in seconds
  local head body
  head=$(b64url "convert_to('{\"alg\":\"HS256\",\"typ\":\"JWT\"}', 'UTF8')")
  body=$(b64url "convert_to(jsonb_build_object('sub', '2', 'iss', 'https://id.example', $1)::text, 'UTF8')")
  echo "SELECT set_config('test.token', m || '.' || $(b64url "authz_int.hmac_sha256(convert_to('s3cret-for-tests', 'UTF8'), convert_to(m, 'UTF8'))"), true)
  FROM (SELECT $head || '.' || $body AS m FROM (SELECT extract(epoch FROM now()) AS now_s) n) t"
}
expect_code "a token is expired at the very moment of its exp" "28000: token expired or not yet valid" -c "RESET ROLE" -c "BEGIN" \
  -c "$(at_now "'exp', now_s")" -c "SET LOCAL ROLE app_user" -c "SELECT authz.login_jwt(current_setting('test.token'))"
check "... and valid from the very moment of its nbf" "2" \
  "RESET ROLE; BEGIN; $(at_now "'exp', now_s + 300, 'nbf', now_s"); SET LOCAL ROLE app_user;
   SELECT authz.login_jwt(current_setting('test.token')); COMMIT;"

echo "-- RSA signatures (PKCS#1 v1.5, SHA-256), checked in SQL"
# keys and signatures made by openssl when the suite runs; a key's modulus and a signature go to SQL as hex
hex() { python3 -c 'import sys; print(open(sys.argv[1], "rb").read().hex())' "$1"; }
modulus() { openssl rsa -in "$T/rsa$1.pem" -noout -modulus 2>/dev/null | cut -d= -f2; }
rsa_n() { echo "authz_int.b2n(decode('$(modulus "$1")', 'hex'))"; }
rsa_ok() { echo "RESET ROLE; SELECT authz_int.rsa_ok($1, $2, ${4:-65537}, $3)"; }   # $1 signature, $2 modulus, $3 message: SQL
printf 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIyIn0' > "$T/msg"
MSG="convert_to('$(cat "$T/msg")', 'UTF8')"
check "bytes read as a number, whatever their count" "t|t|t" \
  "RESET ROLE; SELECT concat_ws('|', authz_int.b2n('\\x0100') = 256, authz_int.b2n('\\x00') = 0,
     authz_int.b2n(decode(repeat('ff', 15), 'hex')) = 1329227995784915872903807060280344575)"
rsa_key() { openssl genrsa -out "$T/rsa$1.pem" "$1" 2>/dev/null; }
rsa_key 2048; rsa_key 3072; rsa_key 4096
# (the first key's modulus must leave room above it, for the signature plus its modulus further down)
while case "$(modulus 2048)" in F*) true;; *) false;; esac; do rsa_key 2048; done
for bits in 2048 3072 4096; do
  openssl dgst -sha256 -sign "$T/rsa$bits.pem" -out "$T/sig$bits" "$T/msg"
  check "a signature of a $bits-bit key is accepted" "t" "$(rsa_ok "decode('$(hex "$T/sig$bits")', 'hex')" "$(rsa_n $bits)" "$MSG")"
done
SIG="decode('$(hex "$T/sig2048")', 'hex')"; N=$(rsa_n 2048)
check "... not for another message" "f" "$(rsa_ok "$SIG" "$N" "convert_to('$(cat "$T/msg")x', 'UTF8')")"
check "... nor with one bit of it changed" "f" "$(rsa_ok "set_byte($SIG, 100, get_byte($SIG, 100) # 1)" "$N" "$MSG")"
check "... nor under another key" "f" "$(rsa_ok "$SIG" "$(rsa_n 3072)" "$MSG")"
check "... nor with a zero byte before it: a signature is as long as its modulus" "f" "$(rsa_ok "'\\x00'::bytea || $SIG" "$N" "$MSG")"
# s + n is the same number as s under the modulus n: a check that only computes would take it for s. Messages are
# signed until the sum still fits the modulus's length (the first key leaves that room: one message in sixteen fits)
OVER=$(python3 - "$T" "$(modulus 2048)" <<'PY'
import pathlib, subprocess, sys
folder, n = pathlib.Path(sys.argv[1]), int(sys.argv[2], 16)
for i in range(2000):
    (folder / "over").write_text(f"message {i}")
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", folder / "rsa2048.pem", folder / "over"], check=True, capture_output=True).stdout
    over = int.from_bytes(sig, "big") + n
    if over < 256 ** len(sig):
        print(f"message {i}", sig.hex(), over.to_bytes(len(sig), "big").hex())
        break
PY
)
read -r _ over_i over_sig over_sum <<< "$OVER"
check "a signature plus its modulus is refused: a signature is below its modulus" "t|f" \
  "RESET ROLE; SELECT concat_ws('|', authz_int.rsa_ok(decode('$over_sig', 'hex'), $N, 65537, convert_to('message $over_i', 'UTF8')),
     authz_int.rsa_ok(decode('$over_sum', 'hex'), $N, 65537, convert_to('message $over_i', 'UTF8')))"
openssl genrsa -out "$T/rsa1024.pem" 1024 2>/dev/null; openssl dgst -sha256 -sign "$T/rsa1024.pem" -out "$T/sig1024" "$T/msg"
check "a key under 2048 bits signs nothing here" "f" "$(rsa_ok "decode('$(hex "$T/sig1024")', 'hex')" "$(rsa_n 1024)" "$MSG")"
# with the exponent 1 a signature is its own encoding, which anyone can write: only 65537 is computed
EM="decode('0001' || repeat('ff', 202) || '003031300d060960864801650304020105000420', 'hex') || sha256($MSG)"
check "an exponent other than 65537 is refused" "f|f" \
  "RESET ROLE; SELECT concat_ws('|', authz_int.rsa_ok($EM, $N, 1, $MSG), authz_int.rsa_ok($SIG, $N, 3, $MSG))"

echo "-- JWT (RS256): the provider's keys stored by the owner, a token checked against the key it names"
jwks() {  # a key set of the keys made above: each argument is bits:kid[:more members, as JSON] (kid -: none)
python3 - "$T" "$@" <<'PY'
import base64, json, pathlib, subprocess, sys
folder, keys = pathlib.Path(sys.argv[1]), []
for spec in sys.argv[2:]:
    bits, kid, *more = spec.split(":", 2)
    n = subprocess.run(["openssl", "rsa", "-in", folder / f"rsa{bits}.pem", "-noout", "-modulus"], check=True, capture_output=True, text=True).stdout.strip().split("=")[1]
    members = json.loads(more[0]) if more else {}
    n = bytes.fromhex(("00" if members.pop("_zero_first", False) else "") + n)
    key = {"kty": "RSA", "n": base64.urlsafe_b64encode(n).rstrip(b"=").decode(), "e": "AQAB"}
    keys.append(key | ({} if kid == "-" else {"kid": kid}) | members)
print(json.dumps({"keys": keys}))
PY
}
rs256() {  # a token signed by a key made above: $1 its bits, $2 the kid it names (-: none), $3 sub, $4 seconds it lasts, $5 more claims
python3 - "$T" "$@" <<'PY'
import base64, json, pathlib, subprocess, sys, time
folder, bits, kid, sub, ttl, extra = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), json.loads(sys.argv[6])
b = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
j = lambda d: b(json.dumps(d, separators=(",", ":")).encode())
msg = j({"alg": "RS256", "typ": "JWT"} | ({} if kid == "-" else {"kid": kid})) + "." + j({"sub": sub, "exp": int(time.time()) + ttl, "iss": "https://id.example"} | extra)
sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", folder / f"rsa{bits}.pem"], input=msg.encode(), check=True, capture_output=True).stdout
print(msg + "." + b(sig))
PY
}
set_jwks() { echo "RESET ROLE; SELECT string_agg(concat_ws(':', kid, change, why), ' | ' ORDER BY i) FROM authz.set_jwks('$1') WITH ORDINALITY AS t(kid, change, why, i)"; }
login() { echo "BEGIN; SELECT authz.login_jwt('$1'); COMMIT;"; }
refused() { expect_code "$1" "28000: invalid token" -c "BEGIN" -c "SELECT authz.login_jwt('$2')"; }   # $1 label, $2 token
refused "an RS256 token, with no key stored" "$(rs256 2048 k1 2 300 '{}')"
SET=$(jwks 2048:k1 '3072:k2:{"use": "sig", "alg": "RS256"}' '4096:ec:{"kty": "EC"}' '4096:enc:{"use": "enc"}' '4096:ops:{"key_ops": ["encrypt"]}' \
  '4096:rs512:{"alg": "RS512"}' 1024:short '4096:e3:{"e": "Aw"}' 4096:k1 '4096:junk:{"n": "!!"}')
check "the owner stores the provider's key set: each key added, or skipped and why" \
  "ec:skipped:not an RSA key | enc:skipped:not a key for signatures | ops:skipped:not a key for signatures | rs512:skipped:for another algorithm than RS256 | short:skipped:a modulus under 2048 bits or over 4096 | e3:skipped:an exponent other than 65537 | k1:skipped:the same kid as a key before it | junk:skipped:no modulus and exponent in base64url | k1:added | k2:added" \
  "$(set_jwks "$SET")"
expect_code "the app role cannot store keys" "42501: permission denied for function set_jwks" -c "SELECT authz.set_jwks('$SET')"
expect_code "... nor read them" "42501: permission denied for table jwt_keys" -c "SELECT count(*) FROM authz.jwt_keys"
check "a token signed by a stored key signs in as bob, with its scope" "2|read" \
  "BEGIN; SELECT authz.login_jwt('$(rs256 2048 k1 2 300 '{"scope": "read"}')'); SELECT authz.uid() || '|' || current_setting('authz.scopes'); COMMIT;"
check "... and one signed by a 3072-bit key" "2" "$(login "$(rs256 3072 k2 2 300 '{}')")"
refused "a token that names a key nobody stored" "$(rs256 4096 k3 2 300 '{}')"
refused "another key's signature under a stored kid" "$(rs256 3072 k1 2 300 '{}')"
refused "an RS256 token that names no key, with two stored" "$(rs256 2048 - 2 300 '{}')"
refused "alg none, naming a stored key" "$(jwt s3cret-for-tests 2 300 '{"_header": {"alg": "none", "kid": "k1"}}')"
# the known way in: an HS256 token signed with the public key, which anyone has, as its secret
refused "an HS256 token signed with the public key as its secret" \
  "$(jwt "$(openssl rsa -in "$T/rsa2048.pem" -pubout 2>/dev/null)" 2 300 '{"_header": {"alg": "HS256", "kid": "k1"}}')"
refused "a token that says ES256: neither a secret nor a stored key checks it" "$(jwt s3cret-for-tests 2 300 '{"_header": {"alg": "ES256", "kid": "k1"}}')"
refused "a token that says RS256, signed with the secret" "$(jwt s3cret-for-tests 2 300 '{"_header": {"alg": "RS256", "kid": "k1"}}')"
expect_code "an RS256 token that expired" "28000: token expired or not yet valid" -c "BEGIN" -c "SELECT authz.login_jwt('$(rs256 2048 k1 2 -10 '{}')')"
expect_code "an RS256 token from another issuer" "28000: token from another issuer" -c "BEGIN" \
  -c "SELECT authz.login_jwt('$(rs256 2048 k1 2 300 '{"iss": "https://evil.example"}')')"
check "an HS256 token still signs in beside the keys" "2" "$(login "$(jwt s3cret-for-tests 2 300 '{}')")"
# the keys rotate: the next set replaces the stored one
check "the next key set replaces the stored one: a key that left is removed, one that stays is kept" "k1:removed | k2:kept" "$(set_jwks "$(jwks 3072:k2)")"
refused "a token signed by a key that left the set" "$(rs256 2048 k1 2 300 '{}')"
check "a token that names no key, with one stored: checked against that one" "2" "$(login "$(rs256 3072 - 2 300 '{}')")"
refused "... and refused when another key signed it" "$(rs256 2048 - 2 300 '{}')"
check "a kid given another key: replaced" "k2:replaced" "$(set_jwks "$(jwks 4096:k2)")"
check "... the new key's tokens sign in (4096 bits)" "2" "$(login "$(rs256 4096 k2 2 300 '{}')")"
refused "... and the old key's no more" "$(rs256 3072 k2 2 300 '{}')"
check "a key with no kid, its modulus written with a zero byte first" "k2:removed | :added" "$(set_jwks "$(jwks '2048:-:{"_zero_first": true}')")"
check "... signs for a token that names no key" "2" "$(login "$(rs256 2048 - 2 300 '{}')")"
refused "... and not for one that names a key" "$(rs256 2048 k1 2 300 '{}')"
NO_KEYS="22023: the key set holds no key to check tokens with (an RSA key for signatures, 2048 to 4096 bits, exponent 65537)"
expect_code "a key set that leaves no key is refused" "$NO_KEYS" -c "RESET ROLE" -c "SELECT authz.set_jwks('$(jwks '4096:ec:{"kty": "EC"}')')"
said=$(psql -X -q -At -d "$DB" -c "SELECT authz.set_jwks('$(jwks '4096:ec:{"kty": "EC"}' 1024:-)')" 2>&1 | grep '^DETAIL:  ')
[ "$said" = "DETAIL:  key ec: not an RSA key; a key with no kid: a modulus under 2048 bits or over 4096" ] &&
  echo "ok    ... saying why each key was skipped" || { echo "FAIL  why each key was skipped: $said"; fails=$((fails + 1)); }
said=$(psql -X -q -At -d "$DB" -c "SELECT authz.set_jwks('{}')" 2>&1 | grep -E '^(DETAIL|HINT):  ' | tr '\n' ' ')
[ "$said" = "DETAIL:  it holds no keys at all HINT:  the stored keys stay as they were (rowstile help AZ719) " ] &&
  echo "ok    ... or that it holds none, with its code (AZ719)" || { echo "FAIL  a key set with no keys: $said"; fails=$((fails + 1)); }
expect_code "... and so is an answer that is no key set" "$NO_KEYS" -c "RESET ROLE" -c "SELECT authz.set_jwks('{\"error\": \"not found\"}')"
expect_code "... and no answer at all" "$NO_KEYS" -c "RESET ROLE" -c "SELECT authz.set_jwks(NULL)"
check "... and the stored keys stay as they were" "2" "$(login "$(rs256 2048 - 2 300 '{}')")"
check "the audit trail says the keys were set, and which" 'set_jwks|[""]' \
  "RESET ROLE; SELECT action || '|' || (detail->'kids')::text FROM authz.audit WHERE action = 'set_jwks' ORDER BY id DESC LIMIT 1"
check "keys alone set JWT login up, without a secret" "2" \
  "RESET ROLE; BEGIN; DELETE FROM authz.settings WHERE key = 'jwt_secret'; SET LOCAL ROLE app_user;
   SELECT authz.login_jwt('$(rs256 2048 - 2 300 '{}')'); ROLLBACK;"
expect_code "... and an HS256 token is then refused, whatever signed it" "28000: invalid token" -c "RESET ROLE" -c "BEGIN" \
  -c "DELETE FROM authz.settings WHERE key = 'jwt_secret'" -c "SET LOCAL ROLE app_user" -c "SELECT authz.login_jwt('$(jwt s3cret-for-tests 2 300 '{}')')"

echo "-- view as (support)"
check "erin (Acme admin) views as carol: carol's files, read-only" "3|3|5|false" \
  "BEGIN; SET LOCAL authz.user_id = 5; SELECT authz.view_as('3', 'ticket 42'); SELECT (SELECT count(*) FROM app.files) || '|' || authz.uid() || '|' || current_setting('authz.acting_user') || '|' || authz.can('file', 11, 'edit'); COMMIT;"
check "... and turns JIT off for the transaction" "off" \
  "BEGIN; SET LOCAL jit = on; SET LOCAL authz.user_id = 5; SELECT authz.view_as('3', 'ticket 42'); SELECT current_setting('jit'); COMMIT;"
expect_code "... and cannot change anything" "42501: this session is read-only (viewing as someone else, or a read-only token)" -c "BEGIN" -c "SET LOCAL authz.user_id = 5" \
  -c "SELECT authz.view_as('3', 'ticket 42')" -c "SELECT authz.share('folder', 2, 'viewer', 'user', 4)"
check "... nor through the rules: viewing as alice, an UPDATE of her own file changes nothing" "0" \
  "BEGIN; SET LOCAL authz.user_id = 5; SELECT authz.view_as('1', 'ticket 47');
   WITH u AS (UPDATE app.files SET body = 'x' WHERE id = 11 RETURNING 1) SELECT count(*) FROM u; ROLLBACK;"
# the scope view-as carries refuses sharing too; without it (the owner's session sets the settings), only the
# read-only check is left to refuse
for call in "share('folder', 1, 'viewer', 'user', 4)" "unshare('folder', 1, 'viewer', 'org', 1, 'member')" \
            "revoke_link('folder', 1, 'no such link')"; do
  got=$(psql -X -q -At -d "$DB" -c "SET ROLE app_user" -c "SET authz.user_id = 5" -c "SET authz.acting_user = '1'" -c "SELECT authz.$call" 2>&1)
  case "$got" in *"this session is read-only"*) echo "ok    ... whatever the scopes: ${call%%(*} is refused as read-only";;
    *) echo "FAIL  ${call%%(*} while viewing as someone, no scope: $got"; fails=$((fails + 1));; esac
done
check "the audit trail has the reason" "ticket 42" \
  "RESET ROLE; SELECT reason FROM authz.audit WHERE action = 'view_as' ORDER BY id DESC LIMIT 1;"
check "... for that transaction only: what the session does next is on record without it" "none" \
  "BEGIN; SET LOCAL authz.user_id = 5; SELECT authz.view_as('3', 'ticket 45'); COMMIT;
   SET authz.user_id = 1; SELECT authz.create_api_key('after the ticket', 'read');
   RESET ROLE; SELECT coalesce(reason, 'none') FROM authz.audit WHERE action = 'create_api_key' ORDER BY id DESC LIMIT 1;"
# a session limited by scopes keeps them while viewing: a key that may view as someone reads no more than its own
# scopes give (without any, a session gets read)
SUPPORT=$(state -c "SET authz.user_id = 5" -c "SELECT authz.create_api_key('support desk', 'support')")
SUPPORT_FILES=$(state -c "SET authz.user_id = 5" -c "SELECT authz.create_api_key('support desk, files', 'support,files')")
check "a key that may only view as someone: viewing as carol, it reads none of her files or folders" "0|0|3|support" \
  "BEGIN; SELECT authz.login_key('$SUPPORT'); SELECT authz.view_as('3', 'ticket 48');
   SELECT (SELECT count(*) FROM app.files) || '|' || (SELECT count(*) FROM app.folders) || '|' || authz.uid() || '|'
          || current_setting('authz.scopes'); COMMIT;"
check "... one with files too: her files, still no folders, read-only" "3|0|false|files,support" \
  "BEGIN; SELECT authz.login_key('$SUPPORT_FILES'); SELECT authz.view_as('3', 'ticket 49');
   SELECT (SELECT count(*) FROM app.files) || '|' || (SELECT count(*) FROM app.folders) || '|' || authz.can('file', 11, 'edit')
          || '|' || current_setting('authz.scopes'); COMMIT;"
# ... and writes nothing, whatever its scopes hold (files: app.files.update): the rules let a session that views as
# someone read only. Alice may edit her own file 11; erin's key, viewing as her, changes nothing
check "... a write its scopes hold: viewing as alice, an UPDATE of her own file changes nothing" "0" \
  "BEGIN; SELECT authz.login_key('$SUPPORT_FILES'); SELECT authz.view_as('1', 'ticket 51');
   WITH u AS (UPDATE app.files SET body = 'x' WHERE id = 11 RETURNING 1) SELECT count(*) FROM u; ROLLBACK;"
check "... which the key alone, signed in as a user who may, would change" "1" \
  "BEGIN; SELECT authz.login_key('$(state -c "SET authz.user_id = 1" -c "SELECT authz.create_api_key('her files', 'files')")');
   WITH u AS (UPDATE app.files SET body = body WHERE id = 11 RETURNING 1) SELECT count(*) FROM u; ROLLBACK;"
check "... and the rule's explanation says why: the session views as someone else" "t" \
  "BEGIN; SELECT authz.login_key('$SUPPORT_FILES'); SELECT authz.view_as('1', 'ticket 52');
   SELECT array_to_string(authz.explain_rule('app.files', 'update', '11'), chr(10))
          LIKE '%no   the session views as someone else: it may not update on app.files%'; ROLLBACK;"
check "... and a session without scopes views with read" "read" \
  "BEGIN; SET LOCAL authz.user_id = 5; SELECT authz.view_as('3', 'ticket 50'); SELECT current_setting('authz.scopes'); COMMIT;"
expect_code "carol cannot view as erin" "42501: you cannot view as user 5" -c "SET authz.user_id = 3" -c "SELECT authz.view_as('5', 'curious')"
expect_code "a reason is required" "22023: say why (the reason is kept in the audit trail)" -c "SET authz.user_id = 5" -c "SELECT authz.view_as('3', '')"
expect_code "one view-as at a time" "42501: already viewing as someone" -c "BEGIN" -c "SET LOCAL authz.user_id = 5" \
  -c "SELECT authz.view_as('3', 'ticket 42')" -c "SELECT authz.view_as('4', 'ticket 43')"
expect_code "an administrator views as a user the database doesn't have" "P0001: there is no active user 999" -c "RESET ROLE" \
  -c "SELECT authz.view_as('999', 'ticket 44')"
caught "... caught at a savepoint: who was signed in before still is" "SELECT authz.act_as('user', '1')" \
  "SELECT authz.view_as('999', 'ticket 44')" "P0001: there is no active user 999"

echo "-- group sync (administrators)"
check "sync Engineering to alice and carol" "1|0" \
  "RESET ROLE; SELECT added || '|' || removed FROM authz.sync_members('team', '10', 'member', ARRAY['1', '3']);"
check "... the audit trail names the group as shares do, however its id is written" "10" \
  "RESET ROLE; BEGIN; SELECT authz.sync_members('team', '010', 'member', ARRAY['1', '3']);
   SELECT object_id FROM authz.audit WHERE action = 'sync_members' ORDER BY id DESC LIMIT 1; ROLLBACK;"
check "... carol is now in Engineering" "t" "SET authz.user_id = 3; SELECT authz.can('folder', 3, 'edit');"
expect_code "the app role cannot sync" "42501: permission denied for function sync_members" -c "SELECT authz.sync_members('team', '10', 'member', ARRAY['4'])"
# NULL is no list (a sync job's failed fetch): the group is left as it is, not emptied
expect_code "a NULL list is refused" "22023: say who the members are: a list of ids with no NULL in it (an empty list for none)" \
  -c "RESET ROLE" -c "SELECT * FROM authz.sync_members('team', '10', 'member', NULL)"
expect_code "... and a list with a NULL in it" "22023: say who the members are: a list of ids with no NULL in it" \
  -c "RESET ROLE" -c "SELECT * FROM authz.sync_members('team', '10', 'member', ARRAY['1', NULL])"
check "... Engineering keeps alice and carol" "1,3" \
  "RESET ROLE; SELECT string_agg(user_id::text, ',' ORDER BY user_id) FROM app.team_members WHERE team_id = 10;"
check "an empty list removes every member" "0|2" \
  "RESET ROLE; BEGIN; SELECT added || '|' || removed FROM authz.sync_members('team', '10', 'member', ARRAY[]::text[]); ROLLBACK;"
expect_code "only a relation from one table of members syncs" \
  "P0001: folder.viewer has no single table of members to sync (it needs one source: table(group -> user), without where)" \
  -c "RESET ROLE" -c "SELECT * FROM authz.sync_members('folder', '1', 'viewer', ARRAY['4'])"

echo "-- a group keyed by two columns, in a policy without impersonate (tests/composite.authz)"
CX="${DB}_cx"
dropdb --if-exists "$CX" 2>/dev/null; createdb "$CX" || exit 1
CXQ() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$CX" "$@" 2>&1; }
python3 compile_policy.py tests/composite.authz > $T/cx.sql || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$CX" -f tests/composite_schema.sql >/dev/null &&
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$CX" -f $T/cx.sql >/dev/null || exit 1
CXQ -c "INSERT INTO cx.users VALUES (1), (2), (3)" -c "INSERT INTO cx.orgs VALUES (1)" \
    -c "INSERT INTO cx.teams (org_id, slug) VALUES (1, 'red team'), (1, 'blue')" \
    -c "INSERT INTO cx.team_members VALUES (1, 'red team', 1), (1, 'blue', 2)" >/dev/null
members="SELECT string_agg(team_slug || ' ' || user_id, ', ' ORDER BY team_slug, user_id) FROM cx.team_members"
got=$(CXQ -c "SELECT added || '|' || removed FROM authz.sync_members('team', '(1,\"red team\")', 'member', ARRAY['2', '3'])" -c "$members" | paste -sd' ')
want="2|1 blue 2, red team 2, red team 3"
[ "$got" = "$want" ] && echo "ok    sync a team keyed by (org_id, slug): its members are the list, the other team's are as they were" ||
  { echo "FAIL  sync a team keyed by two columns: expected '$want', got '$got'"; fails=$((fails + 1)); }
# a link table naming a team by its two columns: the audit trail names the team by its whole id, as authz.share would
got=$(CXQ -c "INSERT INTO cx.folders (org_id, id, owner_id) VALUES (1, 1, 1)" -c "INSERT INTO cx.folder_teams VALUES (1, 1, 'red team')" \
  -c "SELECT subject_id FROM authz.audit WHERE action = 'relate' AND relation = 'editor' ORDER BY id DESC LIMIT 1" | tail -n 1)
[ "$got" = '(1,"red team")' ] && echo "ok    the audit trail names a team linked by two columns by its whole id" ||
  { echo "FAIL  the audit of a link to a team keyed by two columns: $got"; fails=$((fails + 1)); }
got=$(CXQ -c "SET ROLE app_user" -c "SET authz.user_id = 1" -c "SELECT authz.view_as('2', 'ticket 46')" | grep '^ERROR:')
[ "$got" = "ERROR:  you cannot view as user 2" ] && echo "ok    the user type has no impersonate: a user may not view as another" ||
  { echo "FAIL  view as, without impersonate: $got"; fails=$((fails + 1)); }
dropdb "$CX"; rm -f $T/cx.sql

if [ $fails -eq 0 ]; then echo "identity: all passed"; else echo "identity: $fails failed"; exit 1; fi
