# Scale benchmark

Measures rowstile against its scale target (the gate): with 20 tree writes/s arriving steadily
(90% folder creates, 9% moves of small folders, 1% links) and 400 reads/s beside them, tree writes
p95 < 50 ms, reads through RLS p95 < 5 ms, and no failed writes; a big move may pause other tree
writes, and the run reports for how long.

    core/bench/scale.sh                       # 400k files, 20k folders: the dev size, a few minutes
    core/bench/scale.sh --large               # 1M files, 50k folders: the gate's size on the laptop of 2026-10
    core/bench/scale.sh --medium              # 5M files, 250k folders: 8 minutes
    core/bench/scale.sh --full                # 20M files, 1M folders, the gate's own size: 20 minutes, and
                                              # 16 GB for Docker (8 GB of shared buffers)
    KEEP=1 core/bench/scale.sh                # leave the container up (database authz_bench)
    core/bench/regress.sh                     # small run compared with this machine's baseline (CI runs it)

Each run starts a fresh Postgres container from `../Dockerfile` (4 GB shared buffers, 8 GB for `--full`; JIT
off), loads
the example app at scale (`load.sql`: a folder tree exactly 20 levels deep, each level about 1.5 times
wider than the one above; 5% of folders also linked into a folder nearer the top, so no folder ends up
inside itself; 25 folders for each user and for each team from `--large` up, so a user holds the same at
every size), applies `example/docs.authz` with `rowstile apply`, adds shares (`shares.sql`),
then runs `pgbench` (`workload/`, driven by `run.sh`):

1. reads through RLS alone, 400/s: open a file, open a folder, `authz.can`, as random users, a
   quarter of them org admins (who reach every folder);
2. tree writes with 1, 10 and 50 clients: how far does throughput go?
3. the gate: 20 tree writes/s and 400 reads/s arriving steadily, together;
4. one big move (the folder with the most below it, into another root) during steady writes;
5. listing everything a user can see with `authz.list`, whole and in pages of 1,000.

Results are written to `results/`. `latency.py` turns pgbench's per-transaction logs into percentiles; "e2e" adds
the time a transaction waited to start, which is what a caller arriving at that rate sees. Any statement running
longer than four measuring periods is cut off and counted as "timed out", so slow writes can't stretch a run; a
client pgbench stops on any other error (a write the rules refuse, say) is counted apart, as "aborted": a broken
write path, not a slow one. The server and pgbench share the machine's CPUs, and other containers may be running:
compare runs with each other, not with production. A run exits 1 when a gate fails, when `authz.verify()` doesn't
say true after its writes, or when a listing fails.

`regress.sh` runs a small version (10k folders, short steps) and fails when any p95 of steps 1 and 3 (step 3's
writes and reads each have their own, and an "all" row each), or the big move, got more than twice as slow as in
the machine's baseline (and by more than 2 ms, or half a second for the big move), or when the run went wrong: a
write failed, was aborted or timed out, `authz.verify()` didn't say true after the writes, or a listing failed. The
gate's speed limits (reads and writes p95) are shown, not judged (`SPEED_GATES=0`): they are for the gate's size on
a machine of its own, which `scale.sh` judges. Its reads arrive at 25 a second per CPU, at most the gate's 400
(`READ_RATE`): on a 2-CPU CI machine 400 reads/s keep both CPUs busy, and the p95 measures the wait for one (126 ms
there). A script that ran fewer than 50 times isn't judged. A run that is slower runs once more, and only a second
slower run counts: a busy machine is slow for a while, a slower commit is slow both times. A run that went wrong
fails at once. A baseline belongs to the machine that recorded it, so none is committed: the first run on a machine
records one (`core/bench/baseline.txt`, which git ignores), and `regress.sh --record` records it again after an
intended change. CI (GitHub's runners) keeps its own in the Actions cache:
`gh workflow run nightly.yml -f only=bench` records it when there is none.

## Results of 2026-10-03, from a build before the rename

These figures were measured on 2026-10-03 by the build of that day, before the project took the name rowstile:
the result files call it `rowfence 0.1.0-dev`. They ran on PostgreSQL 16, on the laptop the project was
developed on then (16 CPUs, nothing else running), which is out of use. No build since has run these sizes:
read them as what the design cost at each size on that build, not as the speed of this release.

Each column comes from its files in `results/`: `--large` from `2026-10-03-1000000-files-pg16-1.txt` and
`-2.txt`; `--medium` from `2026-10-03-5000000-files-pg16.txt`; `--full` from
`2026-10-03-20000000-files-pg16.txt`, then its measuring steps again on the same database (`-again.txt`).
Latencies are end to end (the "e2e" column).

| p95 | `--large`: 1M files, 50k folders | `--medium`: 5M, 250k | `--full`: 20M, 1M |
|---|---|---|---|
| reads alone | 3.31, 3.20 ms | 3.33 ms | 4.62, 4.24 ms |
| reads beside the gate's writes | 3.21, 3.18 ms | 3.71 ms | 4.57, 4.30 ms |
| tree writes, the gate | 14.5, 16.3 ms | 32.7 ms | 38.4, 28.5 ms |
| the big move | 0.62, 0.56 s (19k below) | 0.91 s (26k below) | 3.68, 2.04 s (54k below) |
| apply, with the backfill | 7 s | 39 s | 191 s |
| `authz.verify()` after the writes | 8 s | 41 s | 144, 151 s |
| the database | 304 MB | 1.5 GB | 6.0 GB |

The gate (tree writes p95 < 50 ms, reads p95 < 5 ms, no failed writes) passes at each size, at `--full` with
little to spare on reads. What `--full` needs from the machine:

- **Memory.** In a Docker VM of 6 GB it swaps, and nothing it measures means anything (reads at a p95 of 23 ms).
  With 16 GB and the 4 GB of shared buffers the smaller sizes use, reads miss the shared buffers on every query
  and their p95 is 5.9 ms; with 8 GB they pass.
- **The same users per folder.** `--full` used to have 20,000 users for its million folders, so each user held
  twice what one holds at the other sizes, and reads took twice as long for that alone: a read costs what its
  reader holds directly (the limits page). It has 40,000 now.

Before `authz.verify()` and the backfill went through the rows in batches, verify at this size took more than
2.4 GB of memory and was killed on the 6 GB VM; it now holds 146 MB.

Reads through the rules run on one CPU: rowstile's functions are not marked parallel safe (a session's signature
is bound to its backend, which a parallel worker is not), so Postgres never splits such a read between workers.
