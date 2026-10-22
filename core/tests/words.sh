# words.sh: how the suites that check refusals compare one (sourced by adversarial.sh, sessions.sh,
# governance.sh, identity.sh and principals.sh).
# An error is read as "SQLSTATE: message" (psql's VERBOSITY=verbose). An expectation gives the SQLSTATE and the
# start of the message ("42501: permission denied: ..."): the words say which check refused, where the code alone
# can't (two guards that answer 42501 look the same). An expectation of the code alone matches nothing.

# psql's output, run with VERBOSITY=verbose -> "SQLSTATE: message" of its last error, or its last line
error_of() {
  local err
  err=$(printf '%s\n' "$1" | grep '^ERROR:  ' | tail -n 1)
  if [ -n "$err" ]; then echo "${err#ERROR:  }"; else printf '%s\n' "$1" | tail -n 1; fi
}

# $1 label, $2 expected, $3 got: whether they agree
agrees() {
  local want=$2 got=$3
  if [[ "$want" =~ ^[0-9A-Z]{5}:\  ]]; then [[ "$got" == "$want"* ]]; return; fi
  [ "$got" = "$want" ]
}
