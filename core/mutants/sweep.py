#!/usr/bin/env python3
"""The mutation sweep: small mistakes put into authzlib by rule (mutants.py), one at a time, and the suites run until
one goes red. A mutant no suite catches is a check that is missing, or a change that can't change an answer: each is
listed in survivors.txt with which, and a new one fails the run. .github/workflows/mutants.yml runs it on GitHub's
runners: `prepare`, then `run` on many runners side by side (one shard each), then `collect`.

    python3 core/mutants/sweep.py list [--since C]                       # every mutant, by operator and file
    python3 core/mutants/sweep.py calls DIR... --source TEXT --out F     # the call data, from CI's coverage artifacts
    python3 core/mutants/sweep.py prepare --out P [--since C | --only ID,... | --limit N] [--shards N]
                                          [--carried DIR] [--calls F] [--stats F]   # the cheap phase, the queues
    python3 core/mutants/sweep.py run --prepared P --shard 1/8 --out R   # one shard: a Postgres container of its own
    python3 core/mutants/sweep.py collect --prepared P --shards R... --out C   # the results, the report, survivors

`run` needs Docker and the image core/Dockerfile builds (rowstile:16); it mutates this checkout's authzlib, which the
container mounts, and puts it back after each mutant. A suite red on a mutant runs again: a catch counts when it is
red twice, and only if the suite is green unmutated on that machine (tried at its first catch). No bytecode is
written or read: a mutation of the same length, written in the same second as the last import, would run the old
code. A shard stops taking mutants after --budget minutes; those left are `not run`, and the next run takes them.

Results: one JSON object a mutant (results.jsonl): its id, where it is, its kind (plan.py), what caught it (a
suite, `compiler fails` or `compiler hangs`), `MISSED`, or why it didn't run (`same`, `unreached`, `not run`,
`error`), its seconds and the suites' order. `--carried` takes a previous run's: the results of mutants whose line
hasn't changed carry over, but for those MISSED and not listed as equivalent, which run again.

The suites' order learns each suite's catches and seconds (stats.json, plan.Stats). No copy is kept in the
repository, which would go stale: `--stats` takes the newest run's (the workflow finds it, whatever results it
carries), else `--carried`'s; without either every suite counts the same until the run learns. collect names the
run in the stats it keeps, and each report says whose stats ordered it."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time
from collections import Counter
from typing import Any

import mutants
import plan

HERE = os.path.dirname(os.path.abspath(__file__))

ROOT = os.path.dirname(os.path.dirname(HERE))
SURVIVORS = os.path.join(HERE, "survivors.txt")
PER_SHARD = 30  # mutants a shard is given when no limit is: about what one runner clears in its budget
BY_COMPILER = ("compiler fails", "compiler hangs")
NOT_RUN = ("same", "unreached")  # final without a suite: equivalent for every output, or no suite runs its lines
Record = dict[str, Any]


def head(root: str) -> str:
    p = subprocess.run(["git", "-C", root, "rev-parse", "--short", "HEAD"], capture_output=True, text=True)
    return p.stdout.strip() or "?"


def read_jsonl(path: str) -> list[Record]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def write_jsonl(path: str, rows: list[Record]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")


def record(m: mutants.Mutant, kind: str, result: str, **more: object) -> Record:
    return {"id": m.id, "file": m.file, "func": m.func, "op": m.op, "line": m.line, "what": m.what, "kind": kind,
            "result": result, "seconds": 0, "order": [], "selected": [], "notes": [], **more}  # fmt: skip


def line_of(r: Record) -> str:
    """A result as one line: `id  result  (seconds)  what  [notes]  [order kind: a*, b, ...]`."""
    notes = "".join(f"  [{n}]" for n in r.get("notes", []))
    order = ", ".join(s + ("*" if s in r.get("selected", []) else "") for s in r.get("order", []))
    return f"{r['id']}  {r['result']}  ({r.get('seconds', 0):.0f}s)  {r['what']}{notes}" + (
        f"  [order {r['kind']}: {order}]" if order else ""
    )


# ---------------------------------------------------------------------------------------------------------------
# The survivors file


SURVIVOR = re.compile(r"(g[0-9a-f]{10}) (equivalent|lead) ([a-z_]+\.py) (\S+): (\S.*)")


def read_survivors(path: str) -> dict[str, tuple[str, str]]:
    """{id: (equivalent or lead, why)} from survivors.txt; a line that doesn't read raises ValueError."""
    out: dict[str, tuple[str, str]] = {}
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            m = SURVIVOR.fullmatch(line)
            if not m:
                raise ValueError(f"{path}:{n}: not `<id> <equivalent|lead> <file> <function>: <why>`: {line}")
            if m.group(1) in out:
                raise ValueError(f"{path}:{n}: {m.group(1)} is listed twice")
            out[m.group(1)] = (m.group(2), m.group(5))
    return out


# ---------------------------------------------------------------------------------------------------------------
# list, calls


def list_mode(args: argparse.Namespace) -> None:
    dropped: Counter[str] = Counter()
    ms = mutants.generate(os.path.join(args.root, "core"), dropped)
    if args.since:
        ms = mutants.in_lines(ms, mutants.changed_lines(args.root, args.since))
    print(f"{len(ms)} mutants at {head(args.root)}" + (f", in lines changed since {args.since}" if args.since else "")
          + f" (left out: {dict(dropped)})")  # fmt: skip
    for title, key in (("operator", "op"), ("file", "file")):
        counts = Counter(getattr(m, key) for m in ms)
        print(f"\n{title:<40}{'mutants':>10}")
        for k, n in counts.most_common():
            print(f"{k:<40}{n:>10}")
    if args.ids:
        for m in ms:
            print(f"{m.id}  {m.what}")


def calls_mode(args: argparse.Namespace) -> None:
    unmapped = plan.refresh_calls(args.dirs, args.source, args.out)
    calls = plan.Calls.load(args.out)
    print(f"{args.out}: {len(calls.functions)} functions, {len(calls.lines)} files, from {args.source}")
    if unmapped:
        print(f"steps that select no suite: {unmapped}")


# ---------------------------------------------------------------------------------------------------------------
# prepare


def deal(predicted: dict[str, float], shards: int) -> dict[str, int]:
    """Each mutant's shard (1 to shards): the longest predicted first, each to the shard with the least so far
    (ties: the lower shard, then the mutant's id), so the shards end about together."""
    load = [0.0] * shards
    out: dict[str, int] = {}
    for mid in sorted(predicted, key=lambda k: (-predicted[k], k)):
        i = min(range(shards), key=lambda j: (load[j], j))
        load[i] += predicted[mid]
        out[mid] = i + 1
    return out


def carried_over(path: str | None, ids: set[str], survivors: dict[str, tuple[str, str]]) -> list[Record]:
    """A previous run's results that still hold: their line is unchanged (the id is still made), and they are final
    (not a MISSED one unless it is listed as equivalent, which runs again; not `not run` nor `error`)."""
    out = []
    for r in read_jsonl(os.path.join(path, "results.jsonl")) if path else []:
        if r["id"] not in ids or r["result"] in ("not run", "error"):
            continue
        if r["result"] == "MISSED" and survivors.get(r["id"], ("",))[0] != "equivalent":
            continue
        out.append({**r, "carried": True})
    return out


def stats_file(stats: str | None, carried: str | None) -> str | None:
    """The stats the order starts from: --stats, else the carried run's, else none."""
    if stats:
        return stats
    if carried and os.path.exists(os.path.join(carried, "stats.json")):
        return os.path.join(carried, "stats.json")
    return None


def learned_by(commit: str) -> str:
    """The run that learned the stats collect keeps: GitHub's run id, the commit and the day."""
    run = os.environ.get("GITHUB_RUN_ID")
    return f"{'run ' + run if run else 'a run by hand'} at {commit}, {time.strftime('%Y-%m-%d', time.gmtime())}"


def prepare(args: argparse.Namespace) -> None:
    core = os.path.join(args.root, "core")
    os.makedirs(args.out, exist_ok=True)
    work = os.path.join(args.out, "work")
    gens = mutants.generate(core)
    by_id = {m.id: m for m in gens}
    survivors = read_survivors(args.survivors)
    carried = carried_over(args.carried, set(by_id), survivors)
    done = {r["id"] for r in carried}
    previous = {r["id"]: r["result"] for r in read_jsonl(os.path.join(args.carried, "results.jsonl"))} if args.carried else {}  # fmt: skip
    if args.only:
        want = [x.strip() for x in args.only.split(",") if x.strip()]
        unknown = [x for x in want if x not in by_id]
        if unknown:
            sys.exit(f"no such mutant at {head(args.root)}: {unknown}")
        candidates, limit = [by_id[x] for x in want], args.limit or None
    elif args.since:
        changed = mutants.in_lines(gens, mutants.changed_lines(args.root, args.since))
        candidates, limit = [m for m in changed if m.id not in done], args.limit or None
    else:
        candidates = [m for m in mutants.spread(gens, args.seed) if m.id not in done]
        limit = args.limit or args.shards * PER_SHARD
    print(f"{len(gens)} mutants at {head(args.root)}; {len(carried)} results carried over; {len(candidates)} "
          f"candidates; to run: {limit or 'all of them that need suites'}", flush=True)  # fmt: skip
    t0 = time.time()
    base = plan.measure(args.root, work)
    calls = plan.Calls.load(args.calls)
    print(f"measured the outputs unmutated in {time.time() - t0:.0f} s; calls: {calls.source}", flush=True)
    rows = plan.cheap(base, calls, work, candidates, args.procs, limit) if candidates else []
    shutil.rmtree(work, ignore_errors=True)
    stats = plan.Stats.load(stats_file(args.stats, args.carried))
    stats.save(os.path.join(args.out, "stats.json"))
    print(f"the suites' order: the stats of {stats.source}", flush=True)
    decided = list(carried)
    queued: list[Record] = []
    for row in rows:
        m = by_id[row["id"]]
        notes = [row["note"]] if row["note"] else []
        if row["kind"] in plan.RUNNABLE:
            order = stats.order(row["selected"])
            # a mutant missed before runs every suite; another, the selected ones (a likely catch among them)
            again = previous.get(m.id) == "MISSED"
            secs = sum(stats.seconds(s) for s in (order if again or not row["selected"] else row["selected"]))
            queued.append({**row, "predicted": round(secs)})
        else:
            decided.append(record(m, row["kind"], row["kind"], selected=row["selected"], notes=notes,
                                  changed=row["changed"]))  # fmt: skip
    shards = min(args.shards, len(queued))
    where = deal({q["id"]: q["predicted"] for q in queued}, shards) if shards else {}
    for q in queued:
        q["shard"] = where[q["id"]]
    queued.sort(key=lambda q: (q["shard"], -q["predicted"], q["id"]))
    queue = {"commit": head(args.root), "calls": calls.source, "stats": stats.source, "shards": shards,
             "mutants": queued}  # fmt: skip
    with open(os.path.join(args.out, "queue.json"), "w", encoding="utf-8") as fh:
        json.dump(queue, fh, indent=1)
    write_jsonl(os.path.join(args.out, "decided.jsonl"), decided)
    kinds = Counter(r["kind"] for r in rows)
    print(f"classified {len(rows)} in {time.time() - t0:.0f} s: {dict(kinds)}; {len(queued)} to run on {shards} "
          f"shards (predicted seconds a shard: {[sum(q['predicted'] for q in queued if q['shard'] == i + 1) for i in range(shards)]})")  # fmt: skip
    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as fh:
            fh.write(f"shards={json.dumps(list(range(1, shards + 1)))}\n")


# ---------------------------------------------------------------------------------------------------------------
# run: one shard, on a Postgres container of its own


class Container:
    """A Postgres container from the suites' image, with this checkout mounted at /src, started as core/ci.sh does."""

    def __init__(self, root: str, image: str, name: str) -> None:
        self.root, self.image, self.name = root, image, name

    def docker(self, *a: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["docker", *a], capture_output=True, text=True, check=check)

    def start(self) -> None:
        self.docker("run", "-d", "--name", self.name, "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
                    "-v", f"{self.root}:/src", self.image,
                    "-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off",
                    "-c", "wal_level=logical")  # fmt: skip
        for _ in range(60):
            if self.docker("exec", self.name, "pg_isready", "-q", "-h", "/var/run/postgresql", check=False).returncode == 0:  # fmt: skip
                break
            time.sleep(1)
        time.sleep(3)  # the image's entrypoint restarts the server once after initdb
        self.docker("exec", "-e", "PGHOST=/var/run/postgresql", "-e", "PGUSER=postgres", "-w", "/src/core", self.name,
                    "bash", "tests/make_owner.sh")  # fmt: skip

    def sh(self, cmd: str, timeout: int, log: str) -> int:
        """Runs cmd in core/ as the suites run (authz_owner, no bytecode written or read), its output to log;
        124: it timed out."""
        with open(log, "w", encoding="utf-8") as fh:
            try:
                p = subprocess.run(
                    ["docker", "exec", "-e", "PGHOST=/var/run/postgresql", "-e", "PGUSER=authz_owner",
                     "-e", "PGSUPERUSER=postgres", "-w", "/src/core", self.name, "env", "-u", "PYTHONPYCACHEPREFIX",
                     "PYTHONDONTWRITEBYTECODE=1", "timeout", "-k", "30", str(timeout), "bash", "-c", cmd],
                    stdout=fh, stderr=subprocess.STDOUT, timeout=timeout + 120,
                )  # fmt: skip
            except subprocess.TimeoutExpired:
                return 124
        return p.returncode

    def clean(self) -> int:
        """Deletes every __pycache__ in the checkout (from inside: the container's are root's); says how many."""
        p = self.docker("exec", self.name, "bash", "-c",
                        "n=$(find /src -name __pycache__ -type d | wc -l); "
                        "find /src -name __pycache__ -type d -prune -exec rm -rf {} +; echo $n", check=False)  # fmt: skip
        try:
            return int(p.stdout.strip() or 0)
        except ValueError:
            return -1

    def remove(self) -> None:
        self.docker("rm", "-f", "-v", self.name, check=False)


def tail(path: str, n: int = 60) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return "".join(fh.readlines()[-n:])


def suite_timeout(stats: plan.Stats, s: str) -> int:
    return int(max(600, 5 * stats.seconds(s)))


class Shard:
    """One shard's run: its container, the stats it learns, the suites it found green or red unmutated."""

    def __init__(self, args: argparse.Namespace, box: Container, stats: plan.Stats) -> None:
        self.args, self.box, self.stats = args, box, stats
        self.verified: set[str] = set()  # green unmutated on this machine
        self.broken: set[str] = set()  # red unmutated here: its catches don't count, and it runs no more
        self.delta: dict[str, Any] = {"catches": {}, "green": {}}
        self.log = os.path.join(args.out, "suite.log")

    def suite(self, name: str) -> tuple[int, float]:
        t = time.time()
        rc = self.box.sh(dict(plan.SUITES)[name], suite_timeout(self.stats, name), self.log)
        secs = time.time() - t
        if rc == 0:
            self.stats.ran_green(name, secs)
            self.delta["green"].setdefault(name, []).append(round(secs, 1))
        return rc, secs

    def green_unmutated(self, name: str, path: str, text: str, mutated: str) -> bool:
        """The suite on the unmutated checkout, once per machine, at its first catch."""
        if name in self.verified:
            return True
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        self.box.clean()
        rc, _ = self.suite(name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(mutated)
        self.box.clean()
        if rc == 0:
            self.verified.add(name)
            return True
        self.broken.add(name)
        return False

    def mutant(self, m: mutants.Mutant, q: Record) -> Record:
        path = os.path.join(self.args.root, "core", "authzlib", m.file)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        if text.count(m.old) != 1:
            return record(m, q["kind"], "error", notes=["its text isn't found once in the file"])
        notes: list[str] = []
        stale = self.box.clean()
        if stale:
            notes.append(f"{stale} __pycache__ found before it, deleted")
        t = time.time()
        order = [s for s in self.stats.order(q["selected"]) if s not in self.broken]
        caught = "MISSED"
        mutated = text.replace(m.old, m.new, 1)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(mutated)
        try:
            for name in order:
                rc, _ = self.suite(name)
                if rc == 0:
                    continue
                # a catch is a suite red twice: under load a suite may go red once on a mutant it passes
                if self.suite(name)[0] == 0:
                    notes.append(f"red once, then green: {name}")
                    continue
                if not self.green_unmutated(name, path, text, mutated):
                    notes.append(f"red unmutated too, not counted: {name}")
                    continue
                caught = name
                if rc == 124:
                    notes.append("timed out")
                self.stats.caught(name)
                self.delta["catches"][name] = self.delta["catches"].get(name, 0) + 1
                os.makedirs(os.path.join(self.args.out, "logs"), exist_ok=True)
                with open(os.path.join(self.args.out, "logs", m.id + ".txt"), "w", encoding="utf-8") as fh:
                    fh.write(f"{m.what}\n{name}, the last lines of its second red run:\n\n{tail(self.log)}")
                break
        finally:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            self.box.clean()
        return record(m, q["kind"], caught, seconds=round(time.time() - t), order=order, selected=q["selected"],
                      notes=[q["note"]] * bool(q["note"]) + notes)  # fmt: skip


def run(args: argparse.Namespace) -> None:
    with open(os.path.join(args.prepared, "queue.json"), encoding="utf-8") as fh:
        queue = json.load(fh)
    i, n = (int(x) for x in args.shard.split("/"))
    if queue["commit"] != head(args.root):
        sys.exit(f"the queue was made at {queue['commit']}, this checkout is at {head(args.root)}")
    mine = [q for q in queue["mutants"] if q["shard"] == i]
    by_id = {m.id: m for m in mutants.generate(os.path.join(args.root, "core"))}
    stats = plan.Stats.load(os.path.join(args.prepared, "stats.json"))
    os.makedirs(args.out, exist_ok=True)
    out = os.path.join(args.out, f"results-{i}.jsonl")
    open(out, "w", encoding="utf-8").close()
    name = args.name or f"rowstile-mutants-{os.getpid()}"
    box = Container(args.root, args.image, name)
    print(f"shard {i} of {n}: {len(mine)} mutants, at {queue['commit']}; container {name}", flush=True)
    box.start()
    shard = Shard(args, box, stats)
    t0 = time.time()
    try:
        for k, q in enumerate(mine, 1):
            m = by_id[q["id"]]
            if time.time() - t0 > args.budget * 60:
                r = record(m, q["kind"], "not run", notes=[f"the shard's {args.budget} minutes were used up"])
            else:
                r = shard.mutant(m, q)
            with open(out, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
            print(f"[{k}/{len(mine)}, {(time.time() - t0) / 60:.0f} min] {line_of(r)}", flush=True)
    finally:
        with open(os.path.join(args.out, f"stats-{i}.json"), "w", encoding="utf-8") as fh:
            json.dump({**shard.delta, "broken": sorted(shard.broken)}, fh, indent=1, sort_keys=True)
        if os.path.exists(shard.log):
            os.remove(shard.log)
        if not args.keep:
            box.remove()


# ---------------------------------------------------------------------------------------------------------------
# collect


def merge_stats(stats: plan.Stats, deltas: list[dict[str, Any]]) -> None:
    for d in deltas:
        for s, k in d.get("catches", {}).items():
            for _ in range(int(k)):
                stats.caught(s)
        for s, secs in d.get("green", {}).items():
            if s in stats.suites:
                for x in secs:
                    stats.ran_green(s, float(x))


def collect(args: argparse.Namespace) -> int:
    with open(os.path.join(args.prepared, "queue.json"), encoding="utf-8") as fh:
        queue = json.load(fh)
    results: dict[str, Record] = {r["id"]: r for r in read_jsonl(os.path.join(args.prepared, "decided.jsonl"))}
    ran: dict[str, Record] = {}
    deltas: list[dict[str, Any]] = []
    for d in args.shards:
        for dirpath, _dirs, files in os.walk(d):
            for f in sorted(files):
                if re.fullmatch(r"results-\d+\.jsonl", f):
                    for r in read_jsonl(os.path.join(dirpath, f)):
                        ran[r["id"]] = r
                elif re.fullmatch(r"stats-\d+\.json", f):
                    with open(os.path.join(dirpath, f), encoding="utf-8") as fh:
                        deltas.append(json.load(fh))
    by_id = {m.id: m for m in mutants.generate(os.path.join(args.root, "core"))}
    for q in queue["mutants"]:  # a shard that never ran, or was stopped before it wrote this one
        if q["id"] not in ran and q["id"] in by_id:
            ran[q["id"]] = record(by_id[q["id"]], q["kind"], "not run", notes=["its shard didn't get to it"])
    results.update(ran)
    rows = sorted(results.values(), key=lambda r: (r["file"], r["line"], r["id"]))
    os.makedirs(args.out, exist_ok=True)
    write_jsonl(os.path.join(args.out, "results.jsonl"), rows)
    with open(os.path.join(args.out, "results.txt"), "w", encoding="utf-8") as fh:
        fh.write(f"# {queue['commit']}; calls from {queue['calls']}\n")
        fh.writelines(line_of(r) + "\n" for r in rows)
    stats = plan.Stats.load(os.path.join(args.prepared, "stats.json"))
    merge_stats(stats, deltas)
    stats.source = learned_by(queue["commit"])
    stats.save(os.path.join(args.out, "stats.json"))
    survivors = read_survivors(args.survivors)
    classified = len(queue["mutants"]) + sum(1 for r in rows if not r.get("carried") and r["id"] not in ran)
    text, new = report(queue, rows, ran, survivors, deltas, len(by_id), classified, args.jobs)
    with open(os.path.join(args.out, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(text)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(text)
    print(text)
    return 1 if new else 0


def report(queue: dict[str, Any], rows: list[Record], ran: dict[str, Record], survivors: dict[str, tuple[str, str]],
           deltas: list[dict[str, Any]], generated: int, classified: int, jobs: int) -> tuple[str, list[str]]:  # fmt: skip
    """The report (Markdown), and the ids of the survivors survivors.txt doesn't list. classified: the mutants
    this run's cheap phase classified (the share of them that needed suites makes the estimate)."""
    caught = [r for r in rows if r["result"] not in ("MISSED", "not run", "error", *NOT_RUN, *BY_COMPILER)]
    compiler = [r for r in rows if r["result"] in BY_COMPILER]
    missed = [r for r in rows if r["result"] == "MISSED"]
    equivalent = [r for r in missed if survivors.get(r["id"], ("",))[0] == "equivalent"]
    new = [r["id"] for r in missed if r["id"] not in survivors]
    this = [r for r in ran.values() if r["result"] not in ("not run", "error")]
    judged = len(caught) + len(compiler) + len(missed) - len(equivalent)
    out = [f"## Mutants at {queue['commit']}", ""]
    out.append(f"This run: {len(this)} mutants run, {sum(r['result'] == 'not run' for r in ran.values())} left for "
               f"the next run, {sum(r['result'] == 'error' for r in rows)} errors; results carried over from before: "
               f"{sum(bool(r.get('carried')) for r in rows)}. Calls from {queue['calls']}; the suites' order from "
               f"the stats of {queue['stats']}.")  # fmt: skip
    out.append("")
    if judged:
        out.append(f"**Score: {len(caught) + len(compiler)} of {judged} caught "
                   f"({100 * (len(caught) + len(compiler)) / judged:.1f}%)**: {len(caught)} by a suite, "
                   f"{len(compiler)} by the compiler, {len(missed) - len(equivalent)} missed; "
                   f"{len(equivalent)} equivalent left out.")  # fmt: skip
        out.append("")
    if new:
        out += [f"**{len(new)} new survivors**: list each in core/mutants/survivors.txt (equivalent, or a lead: the "
                "check to write), or write the check that catches it.", ""]  # fmt: skip
    if missed:
        out += ["| survivor | verdict | the mutant |", "|---|---|---|"]
        for r in missed:
            verdict = survivors.get(r["id"], ("**new**", ""))[0]
            what = r["what"].replace("|", "\\|")
            out.append(f"| `{r['id']}` | {verdict} | `{what}` |")
        out.append("")
    gone = sorted(set(survivors) - {r["id"] for r in missed} & {r["id"] for r in caught + compiler})
    if gone:
        out += [f"Listed in survivors.txt and caught now (take them out): {', '.join(gone)}", ""]
    by = Counter(r["result"] for r in caught)
    if by:
        out.append(
            "Caught by: " + ", ".join(f"{s} {n}" for s, n in by.most_common()) + f"; the compiler {len(compiler)}."
        )
        out.append("")
    kinds = Counter(r["kind"] for r in rows)
    out.append("Kinds (results so far): " + ", ".join(f"{k} {n}" for k, n in kinds.most_common()) + ".")
    broken = sorted({s for d in deltas for s in d.get("broken", [])})
    if broken:
        out += ["", f"Red unmutated on a runner (their catches not counted): {', '.join(broken)}."]
    secs = [float(r["seconds"]) for r in this if r["result"] not in BY_COMPILER]
    if secs:
        left = generated - len([r for r in rows if r["result"] not in ("not run", "error")])
        share = len(queue["mutants"]) / max(1, classified)
        mean = statistics.mean(secs)
        hours = left * share * mean / 3600
        out += ["", f"Time: {mean / 60:.1f} min a mutant on a runner (median {statistics.median(secs) / 60:.1f}, "
                    f"the longest {max(secs) / 60:.0f}), {sum(secs) / 3600:.1f} runner-hours this run. Left: {left} of "
                    f"{generated} mutants without a result; at this run's share that needs suites and its time, about "
                    f"{hours:.0f} runner-hours, {hours / jobs:.0f} hours with {jobs} jobs side by side."]  # fmt: skip
    out.append("")
    return "\n".join(out), new


# ---------------------------------------------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=ROOT, help="the checkout (core/ inside); this file's by default")
    sub = ap.add_subparsers(dest="mode", required=True)
    p = sub.add_parser("list", help="every mutant, counted by operator and file")
    p.add_argument("--since", help="only those in lines changed since this commit")
    p.add_argument("--ids", action="store_true", help="and each one's id and what it does")
    p = sub.add_parser("calls", help="the call data, from coverage directories (CI's coverage-pg16-* artifacts)")
    p.add_argument("dirs", nargs="+")
    p.add_argument("--source", required=True, help="where the data comes from (the reports say it)")
    p.add_argument("--out", required=True)
    p = sub.add_parser("prepare", help="the cheap phase, and the shards' queues")
    p.add_argument("--out", required=True)
    p.add_argument("--since", help="the mutants in lines changed since this commit")
    p.add_argument("--only", help="g...,g...: these mutants")
    p.add_argument("--limit", type=int, default=0, help="this many that need suites (default: shards x 30)")
    p.add_argument("--shards", type=int, default=8)
    p.add_argument("--carried", help="a previous run's results (results.jsonl, stats.json)")
    p.add_argument("--calls", help="the call data (sweep.py calls); without it, every suite in the stats' order")
    p.add_argument("--stats", help="the stats the order starts from (a run's stats.json); default: --carried's")
    p.add_argument("--survivors", default=SURVIVORS)
    p.add_argument("--procs", type=int, default=os.cpu_count() or 2)
    p.add_argument("--seed", type=int, default=1, help="the order mutants are taken in (mutants.spread)")
    p.add_argument("--github-output", help="where to write shards=[1, ...] for the workflow")
    p = sub.add_parser("run", help="one shard's mutants, on a Postgres container of its own")
    p.add_argument("--prepared", required=True)
    p.add_argument("--shard", required=True, help="i/n")
    p.add_argument("--out", required=True)
    p.add_argument("--image", default="rowstile:16")
    p.add_argument("--name", help="the container's name (default rowstile-mutants-<pid>)")
    p.add_argument("--budget", type=float, default=270, help="minutes after which no mutant is started")
    p.add_argument("--keep", action="store_true", help="leave the container")
    p = sub.add_parser("collect", help="the shards' results together: results, stats, report; 1 if a survivor is new")
    p.add_argument("--prepared", required=True)
    p.add_argument("--shards", nargs="+", default=[], help="directories holding results-<i>.jsonl and stats-<i>.json")
    p.add_argument("--out", required=True)
    p.add_argument("--survivors", default=SURVIVORS)
    p.add_argument("--summary", help="also append the report here (GITHUB_STEP_SUMMARY)")
    p.add_argument("--jobs", type=int, default=8, help="jobs side by side, for the estimate")
    args = ap.parse_args()
    for k in ("root", "out", "prepared", "carried", "calls", "stats", "survivors"):  # the compile helper runs in core/
        if getattr(args, k, None):
            setattr(args, k, os.path.abspath(getattr(args, k)))
    if args.mode == "list":
        list_mode(args)
    elif args.mode == "calls":
        calls_mode(args)
    elif args.mode == "prepare":
        prepare(args)
    elif args.mode == "run":
        run(args)
    elif args.mode == "collect":
        return collect(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
