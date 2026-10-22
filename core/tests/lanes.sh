# lanes.sh: run_tests.sh's lanes (it sources this; not a suite). The steps of a part (policy, command, random) run
# in ROWSTILE_LANES lanes side by side, against the same server: 3 unless it says (CI's runners have 4 cores); 1:
# each step after the other, in the order run_tests.sh writes them. Each lane runs a fixed list: the part's units,
# the longest first to the lane with least to do so far. Steps that share a database or a file are one unit, in
# one lane; no two units share either (each suite's databases, roles and files have names of its own). A step's
# output is kept until it ends, then printed whole, in the order the steps are written (a whole run: part after
# part), so the log reads as one step after the other does; a `--- passed:` line's seconds are while others ran.
# Uses run_tests.sh's `failed` and STEPS_RUN, and its `record` calls lane_next after each result.
LANES=${ROWSTILE_LANES:-3}
case "$LANES" in *[!0-9]*|""|0) echo "ROWSTILE_LANES is a number of lanes, 1 or more, not '$LANES'"; exit 2;; esac
UNITS=()
# unit PART SECONDS COMMAND...: a share of a part's work for one lane, SECONDS long (measured with coverage on, as
# CI runs); run now when there is one lane, else later by run_lanes
unit() { if [ "$LANES" -eq 1 ]; then "${@:3}"; else UNITS+=("$*"); fi; }
# in a lane: the unit's output goes into DIR/N.0, then DIR/N.1 after its first result, and so on; DIR/N.results
# has each result, DIR/N.<k>.done says the file k is whole, and DIR/N.end that the unit ended
lane_unit() {
  LANE_OUT=$1/$2 LANE_SEG=0
  exec > "$LANE_OUT.0" 2>&1
  "${@:3}"
  : > "$LANE_OUT.end"
}
lane_next() {
  printf '%s\t%s\n' "$1" "$2" >> "$LANE_OUT.results"
  : > "$LANE_OUT.$LANE_SEG.done"
  LANE_SEG=$((LANE_SEG + 1))
  exec > "$LANE_OUT.$LANE_SEG" 2>&1
}
# run_lanes PART: the units of PART, in $LANES lanes; prints each unit's output as above, and takes its results
run_lanes() {
  local p=$1 i k s best dir rc name
  local -a mine=() load=() lane=() pids=()
  for i in "${!UNITS[@]}"; do [ "${UNITS[i]%% *}" = "$p" ] && mine+=("$i"); done
  [ ${#mine[@]} -gt 0 ] || return 0
  for ((k = 0; k < LANES; k++)); do load[k]=0; done
  # the longest first (in the order written when as long), each to the lane with least to do so far
  for i in $(for i in "${mine[@]}"; do set -- ${UNITS[i]}; echo "$2 $i"; done | sort -s -k1,1nr | cut -d' ' -f2); do
    best=0
    for ((k = 1; k < LANES; k++)); do [ "${load[k]}" -lt "${load[best]}" ] && best=$k; done
    set -- ${UNITS[i]}; load[best]=$((load[best] + $2)); lane[i]=$best
  done
  # (named so: core/ci.sh shows what a step still running at its limit had printed)
  dir=$(mktemp -d /tmp/rowstile-lanes.XXXXXX) || return 1
  echo "part $p in $LANES lanes, about ${load[*]} seconds each (ROWSTILE_LANES=1: one step after the other)"
  # Ctrl-C or a stop: every lane and what it runs stops too (they are in this process group)
  trap 'trap "" TERM; kill 0; exit 130' INT TERM
  for ((k = 0; k < LANES; k++)); do
    (
      for i in "${mine[@]}"; do
        [ "${lane[i]}" = "$k" ] || continue
        set -- ${UNITS[i]}
        ( lane_unit "$dir" "$i" "${@:3}" )
        [ -e "$dir/$i.end" ] || : > "$dir/$i.lost"
      done
    ) < /dev/null &
    pids[k]=$!
  done
  for i in "${mine[@]}"; do
    s=0
    while :; do
      if [ -e "$dir/$i.end" ]; then
        while [ -e "$dir/$i.$s" ]; do cat "$dir/$i.$s"; s=$((s + 1)); done
        break
      elif [ -e "$dir/$i.$s.done" ]; then
        cat "$dir/$i.$s"; s=$((s + 1))
      elif [ -e "$dir/$i.lost" ] || ! kill -0 "${pids[lane[i]]}" 2>/dev/null; then
        [ -e "$dir/$i.end" ] && continue
        # the unit stopped before its end (a step exited the shell, or its lane was stopped): what it printed
        while [ -e "$dir/$i.$s" ]; do cat "$dir/$i.$s"; s=$((s + 1)); done
        set -- ${UNITS[i]}; echo "--- FAILED: ${*:3} stopped before its end"; failed+=("${*:3} (stopped)")
        break
      else
        sleep 0.5
      fi
    done
    if [ -e "$dir/$i.results" ]; then
      while IFS=$'\t' read -r rc name; do
        STEPS_RUN=$((STEPS_RUN + 1)); [ "$rc" -eq 0 ] || failed+=("$name")
      done < "$dir/$i.results"
    fi
  done
  wait
  trap - INT TERM
  rm -rf "$dir"
}
