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
    gh workflow run nightly.yml -f only=scale -f size=large   # a size (dev, large, medium, full) on one of
                                              # GitHub's runners; the result is the run's `scale` file

Each run starts a fresh Postgres container from `../Dockerfile` (4 GB shared buffers, 8 GB for `--full`; JIT
off), loads
the example app at scale (`load.sql`: a folder tree exactly 20 levels deep, each level about 1.5 times
wider than the one above; 5% of folders also linked into a folder nearer the top, so no folder ends up
inside itself; 25 folders for each user and 250 for each team from `--large` up, so a user holds the same at
every size), applies `example/docs.authz` with `rowstile apply` as the tables' owner, not a superuser (as
`tests/make_owner.sh` makes it), adds shares (`shares.sql`), then runs `pgbench` (`workload/`, driven by
`run.sh`), each read signed in with `authz.act_as`, as an app signs in:

1. reads through RLS alone, 400/s: open a file, open a folder, `authz.can`, as random users, a
   quarter of them org admins (who reach every folder);
2. tree writes with 1, 10 and 50 clients: how far does throughput go?
3. the gate: 20 tree writes/s and 400 reads/s arriving steadily, together;
4. one big move (the folder with the most below it, into another root) during steady writes;
5. listing everything a user can see with `authz.list`, whole and in pages of 1,000;
6. opening a folder as six members made for this step: three are shared 100, 1,000 and 4,000 folders, three are
   the one member of a team given as many. One client each, one after the other. A read by key costs what its
   reader holds ([the limits](../../docs/reference/limits.md)), and this step measures it, each way of holding.
   The six are past the users the other steps draw from, so those steps' data is what it was without them.

Results are written to `results/`. `latency.py` turns pgbench's per-transaction logs into percentiles; "e2e" adds
the time a transaction waited to start, which is what a caller arriving at that rate sees. Any statement running
longer than four measuring periods is cut off and counted as "timed out", so slow writes can't stretch a run; a
client pgbench stops on any other error (a write the rules refuse, say) is counted apart, as "aborted": a broken
write path, not a slow one. The server and pgbench share the machine's CPUs, and other containers may be running:
compare runs with each other, not with production. A run exits 1 when a gate fails, when a read or a write of any
step failed, was aborted or timed out, when the big move failed, when `authz.verify()` doesn't say true after its
writes, or when a listing fails.

`regress.sh` runs a small version (10k folders, short steps) and fails when any p95 of steps 1 and 3 (step 3's
writes and reads each have their own, and an "all" row each), or the big move, got more than twice as slow as in
the machine's baseline (and by more than 2 ms, or half a second for the big move), or when the run went wrong: a
read or a write failed, was aborted or timed out, the big move failed, `authz.verify()` didn't say true after the
writes, or a listing failed. The
gate's speed limits (reads and writes p95) are shown, not judged (`SPEED_GATES=0`): they are for the gate's size on
a machine of its own, which `scale.sh` judges. Its reads arrive at 25 a second per CPU, at most the gate's 400
(`READ_RATE`): on a 2-CPU CI machine 400 reads/s keep both CPUs busy, and the p95 measures the wait for one (126 ms
there). A script that ran fewer than 50 times isn't judged, but one the baseline judged that ran fewer than 25
times fails: it stopped part way. A run that is slower runs once more, and only a second
slower run counts: a busy machine is slow for a while, a slower commit is slow both times. A run that went wrong
fails at once. A baseline belongs to the machine that recorded it, so none is committed: the first run on a machine
records one (`core/bench/baseline.txt`, which git ignores), and `regress.sh --record` records it again after an
intended change. CI (GitHub's runners) keeps its own in the Actions cache:
`gh workflow run nightly.yml -f only=bench` records it when there is none.

## Results of 2026-11-14 and 15, on GitHub's runners

`main` at 0.1.0-dev (commits e042e24b and b7268bcf), PostgreSQL 16.16, each run started by `gh workflow run
nightly.yml -f only=scale -f size=...`. A runner has 4 CPUs and 16 GB, shared by the server and pgbench, on a host
that runs other machines' work too: the gate's speed limits are shown there, not judged.

Each column comes from its files in `results/`: `--large` from `2026-11-14-1000000-files-pg16-runner-1.txt` and
`-2.txt` and the two of `2026-11-15`; `--medium` from `2026-11-14-5000000-files-pg16-runner.txt` and that of
`2026-11-15`; `--full` from `2026-11-14-20000000-files-pg16-runner.txt`. A file's first lines name its commit and
its CPU. Latencies are end to end (the "e2e" column).

| p95 | `--large`, four runs | `--medium`, two runs | `--full`, one run |
|---|---|---|---|
| reads alone | 4.0 to 10.0 ms | 3.6, 5.1 ms | 17.1 ms |
| reads beside the gate's writes | 4.6 to 13.8 ms | 4.2, 6.6 ms | 38.4 ms |
| tree writes, the gate | 24 to 70 ms | 31, 73 ms | 627 ms |
| the big move | 0.71 to 0.97 s (16k to 18k below) | 1.07, 1.26 s (25k below) | 4.38 s (54k below) |
| apply, with the backfill | 8 to 13 s | 57, 75 s | 312 s |
| `authz.verify()` after the writes | 9 to 13 s | 37, 47 s | 244 s |
| tree writes a second, 1 client | 155 to 237 | 172, 236 | 83 |
| tree writes a second, 10 clients | 187 to 294 | 206, 279 | 151 |
| tree writes a second, 50 clients | 158 to 257 | 168, 229 | 121 |
| the database | 322 to 330 MB | 1.6 GB | 6.5 GB |

No run had a failed, aborted or timed-out read or write, and `authz.verify()` said true after each.

- **One runner is not another.** Runs of the same size half an hour apart gave reads beside the writes a p95 of
  4.6 ms on one runner and of 13.8 ms on another: their CPUs differ, and so does what else their hosts run. Compare the rows
  of one run with each other, or two builds in one job. A figure from one runner against a figure from another
  says little.
- **`--full` is too big for a runner.** 8 GB of shared buffers and a 6.5 GB database leave its 16 GB nothing for
  the system. It ran to the end, which says the size works there; its latencies say the machine is too small. The
  figures of 2026-10-03, below, are still the ones for that size.
- **The gate's limits** (tree writes p95 < 50 ms, reads p95 < 5 ms) are for a machine of its own. The fastest
  runner met them at `--large` and at `--medium`; the others didn't.

Step 6, a folder opened by a reader who holds more (p50, one client; the runs of 2026-11-15, `main` at b7268bcf):

| the reader | `--large`, two runs | `--medium` |
|---|---|---|
| is shared 100 folders | 1.39, 1.75 ms | 1.03 ms |
| is shared 1,000 | 1.54, 1.94 ms | 1.17 ms |
| is shared 4,000 | 2.22, 2.72 ms | 1.61 ms |
| has a team given 100 | 1.47, 1.81 ms | 1.07 ms |
| has a team given 1,000 | 1.70, 2.14 ms | 1.24 ms |
| has a team given 4,000 | 2.48, 3.11 ms | 1.79 ms |

Within a run, a reader who holds 4,000 folders pays 1.5 to 1.7 times what one who holds 100 pays.

## Results of 2026-11-15, on a server shared with other work

`main` at c0c33d09, PostgreSQL 16.16, `core/bench/scale.sh --large` and `--full` run by hand on a rented server:
12 CPUs (AMD EPYC), 47 GB, shared by the server and pgbench, on a host that runs other machines' work and beside
another project's services. It has the memory `--full` asks for, which a runner lacks. Its files in `results/`:
`2026-11-15-1000000-files-pg16-vps.txt` and `2026-11-15-20000000-files-pg16-vps.txt`.

| p95 | `--large` | `--full` |
|---|---|---|
| reads alone | 38.9 ms (p50 7.2) | 16.9 ms (p50 7.9) |
| reads beside the gate's writes | 12.6 ms | 206 ms |
| tree writes, the gate | 44.8 ms | 303 ms |
| the big move | 1.30 s (16k below) | 9.44 s (53k below) |
| apply, with the backfill | 17 s | 681 s |
| `authz.verify()` after the writes | 13 s | 398 s |
| tree writes a second, 1 client | 85 | 44 |
| tree writes a second, 10 clients | 100 | 74 |
| tree writes a second, 50 clients | 73 | 67 |
| the database | 330 MB | 6.5 GB |

Neither run had a failed, aborted or timed-out read or write, and `authz.verify()` said true after each.

- **This server is slower than a runner.** At `--large`, with the same build, a read's median is 7.2 ms here
  against 2.1 and 3.3 ms on the two runners of 2026-11-15, one client makes 85 tree writes a second against 185
  and 237, and a reader who is shared 100 folders opens one in 3.6 ms against 1.4 and 1.8. Two to three and a
  half times: its figures say what this machine does, and the gate's limits are not judged on it.
- **What it adds is the full size with memory to spare**, on this build: it ran to the end, with nothing failed.
  Between the two sizes on this one machine, twenty times apart, a read's median went from 7.2 to 7.9 ms, and one
  client's tree writes from 85 to 44 a second. Loading, applying and vacuuming took forty of the run's fifty-one
  minutes.
- The figures of 2026-10-03, below, are still the ones from a machine of its own.

## Results of 2026-10-03, on a machine of its own, from a build before the rename

These figures were measured on 2026-10-03 by the build of that day, before the project took the name rowstile:
the result files call it `rowfence 0.1.0-dev`. They ran on PostgreSQL 16, on the laptop the project was
developed on then (16 CPUs, nothing else running), which is out of use. They are the last runs on a machine of
its own: read them as what the design cost at each size on that build, and the runners' figures above as what
this build does on a shared machine.

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
