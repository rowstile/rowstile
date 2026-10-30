#!/bin/bash
# compile.sh T: checks 9 and 14, which compile Rust (test.sh runs it in the Rust container, in this app's folder,
# with the suite's environment; T is its scratch folder).
# 9: the committed names are the ones rowstile client writes from the policy, and a program that uses them builds,
#    unless it names a permission the policy doesn't have, or gives a plain string where the SDK takes one.
# 14: in a copy of the app, the policy changes; rowstile migrate writes the next migration (after the folder's last
#    one, whatever its number), sqlx's migrator runs it alone on a copy of the migrated test database, rowstile
#    client writes the new names, and a program that uses them asks the database.
set -u
T=$1
HERE=$PWD
ROOT=$(cd ../.. && pwd)
BIN=$CARGO_TARGET_DIR/debug
rc=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1"; rc=1; }
# a copy of the app in folder $1, on the SDK where it is
copy() {
  rm -rf "$1" && cp -r "$HERE" "$1" && sed -i "s|path = \"../../sdk/rust\"|path = \"$ROOT/sdk/rust\"|" "$1/Cargo.toml"
}

# 9: the names, then each use of them built (cargo check), as it must or mustn't
if python3 "$ROWSTILE_CLI" client rust db/policy.authz | diff - src/authz.rs >"$T/names.diff"; then
  W=$T/check9
  copy "$W" && mkdir -p "$W/src/bin"
  said=()
  while IFS='|' read -r code wrong; do
    cat >"$W/src/bin/check9.rs" <<EOF
use conformance::authz::*;

async fn ask(mut tx: sqlx::Transaction<'static, sqlx::Postgres>) -> Result<(), rowstile::Error> {
    $code;
    Ok(())
}

fn main() {
    let _ = ask;
}
EOF
    (cd "$W" && cargo check --locked --quiet --bin check9 --message-format short) >"$T/check9.log" 2>&1
    built=$?
    if { [ -z "$wrong" ] && [ $built = 0 ]; } || { [ -n "$wrong" ] && [ $built != 0 ] && grep -qF "$wrong" "$T/check9.log"; }; then
      :
    else
      said+=("$code: built $([ $built = 0 ] && echo yes || echo no): $(cat "$T/check9.log")")
    fi
  done <<'CASES'
let _ = rowstile::sqlx::can(&mut tx, NotePermission::Edit, 1).await?|
let _ = rowstile::sqlx::perms_of::<ProjectPermission>(&mut tx, &[1, 3]).await?|
let _ = rowstile::sqlx::list(&mut tx, ProjectPermission::View, None).await?; let _ = NOTE|
let _ = rowstile::sqlx::can(&mut tx, NotePermission::Edt, 1).await?|named `Edt` found for enum `conformance::authz::NotePermission`
let _ = rowstile::sqlx::can(&mut tx, NtePermission::Edit, 1).await?|use of undeclared type `NtePermission`
let _ = rowstile::sqlx::can(&mut tx, "edit", 1).await?|the trait `Permission` is not implemented for `&str`
let _ = rowstile::sqlx::perms_of::<String>(&mut tx, &[1]).await?|the trait `Permission` is not implemented for `String`
CASES
  if [ ${#said[@]} = 0 ]; then
    ok "9: the generated names type-check, and a wrong permission name doesn't: in the generated names, and in the SDK's own calls"
  else
    printf '%s\n' "${said[@]}"; bad "9: the generated names, or the SDK's calls, don't build as they must"
  fi
else
  cat "$T/names.diff"; bad "9: src/authz.rs is out of date: run rowstile client"
fi

# 14: a policy change, shipped as the next migration
W=$T/change
copy "$W" || exit 1
cd "$W" || exit 1
sed -i 's/^  can read = recipient$/  can read = recipient\n  can reply = recipient/' db/policy.authz
there=$(ls migrations/*.sql | wc -l)
last=$(ls migrations/*.sql | tail -1)
next=$(printf '%04d_authz_' $((there + 1)))
python3 "$ROWSTILE_CLI" migrate >"$T/change.log" 2>&1 &&
  # sqlx's migrator migrates the database: the new migration alone is left to run
  "$BIN/migrate" "$ROWSTILE_CHANGE_URL" migrations >"$T/applied.log" 2>&1 &&
  python3 "$ROWSTILE_CLI" client >>"$T/change.log" 2>&1 || { cat "$T/change.log" "$T/applied.log"; bad "14: rowstile migrate, sqlx or rowstile client"; exit 1; }
mkdir -p src/bin
cat >src/bin/replies.rs <<'EOF'
// what the app's code does with the names the policy now makes: it names reply, and the database answers it
use conformance::authz::MessagePermission;
use rowstile::Principal;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let pool = sqlx::PgPool::connect(&args[1]).await.expect("the app's pool");
    for user in ["2", "1"] {
        // bo, to whom it is sent, may reply; ann, who sent it, may not even read it
        let mut tx = rowstile::sqlx::begin(&pool, &Principal::user(user)).await.expect("signed in");
        let reply = rowstile::sqlx::can(&mut tx, MessagePermission::Reply, &args[2]).await.expect("reply");
        let read = rowstile::sqlx::can(&mut tx, MessagePermission::Read, &args[2]).await.expect("read");
        println!("{reply} {read}");
    }
}
EOF
got=$(cargo run --locked --quiet --bin replies -- "$ROWSTILE_CHANGE_APP_URL" 1 2>"$T/replies.log")
wrote=$(ls migrations | grep -c "^$next")
# the new migration named after the last one there ($last), and it alone applied
if [ "$got" = "$(printf 'true true\nfalse false')" ] && [ "$wrote" = 1 ] && [ "$(grep -c '^applied' "$T/applied.log")" = 1 ] &&
  grep -q "^applied migrations/$((there + 1)) authz" "$T/applied.log" && grep -q "^    Reply,$" src/authz.rs; then
  ok "14: after a policy change and a new migration, the app works with the new generated names"
else
  cat "$T/applied.log" "$T/replies.log"; echo "replies: $got; $next files: $wrote"; bad "14: a policy change"
fi
exit $rc
