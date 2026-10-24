"""The action's comment: the review posted on the pull request, or the comment posted before updated in place (the one
that starts with the review's marker, written by the token's own account: anyone may write a comment that starts so). The standard library only: a self-hosted runner may not have the GitHub CLI.

A pull request from a fork gets a read-only token, whatever the workflow's permissions ask for. GitHub refuses the
comment then (403): the review stays in the run's summary, a notice says so, and the step passes. A review longer
than a comment may be is cut, and the comment says the whole review is in the run's summary.

It reads the review from $RUNNER_TEMP/rowstile-review.md, and TOKEN, PR, REPO and FORK ("true" for a pull request
from a fork) from the step's environment, with what GitHub gives every step (GITHUB_API_URL, GITHUB_SERVER_URL,
GITHUB_RUN_ID)."""

import json
import os
import sys
import urllib.error
import urllib.request
from typing import TypedDict, cast

MARK = "<!-- rowstile review -->"
# GitHub refuses a comment over 65,536 characters; what is cut stays under it with room to spare
LIMIT = 60_000


class Author(TypedDict):
    login: str
    type: str


class Comment(TypedDict):
    id: int
    body: str
    user: Author


def cut(body: str, rest: str, limit: int = LIMIT) -> str:
    """The comment: the review whole when it fits, else its first lines, any <details> left open closed, and then
    where the rest is."""
    if len(body) <= limit:
        return body
    note = f"\n\n**The review is longer than a comment may be. The rest is in [the run's summary]({rest}).**\n"
    lines = body.split("\n")
    kept: list[str] = []
    size = 0
    for line in lines:
        # room for the note and a closing </details>
        if size + len(line) + 1 > limit - len(note) - len("\n\n</details>"):
            break
        kept.append(line)
        size += len(line) + 1
    text = "\n".join(kept)
    if text.count("<details>") > text.count("</details>"):
        text += "\n\n</details>"
    return text + note


def call(method: str, url: str, token: str, body: dict[str, str] | None = None) -> object:
    req = urllib.request.Request(
        url,
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(req) as res:
        return json.load(res)


def account(token: str) -> str | None:
    """The login the token writes as, or None for an app's token (the workflow's own, GITHUB_TOKEN, writes as
    github-actions[bot]), which GitHub doesn't answer /user for."""
    try:
        return cast(dict[str, str], call("GET", f"{os.environ['GITHUB_API_URL']}/user", token))["login"]
    except (urllib.error.HTTPError, KeyError, TypeError):
        return None


def ours(c: Comment, me: str | None) -> bool:
    """Whether a comment is the review's: it starts with the marker, and the token's account wrote it (for an app's
    token, an app: a person can't write as one)."""
    who = c.get("user") or {"login": "", "type": ""}
    return c["body"].startswith(MARK) and (who["login"] == me if me else who["type"] == "Bot")


def refusal(e: urllib.error.HTTPError) -> str:
    """What GitHub said when it refused: its status and its message."""
    try:
        said = json.loads(e.read()).get("message", "")
    except (ValueError, AttributeError, OSError):
        said = ""
    said = f"HTTP {e.code}" + (f": {said}" if said else "")
    # a workflow command's message: % and line breaks escaped
    return said.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main() -> int:
    env = os.environ
    token, pr = env["TOKEN"], env["PR"]
    api = f"{env['GITHUB_API_URL']}/repos/{env['REPO']}/issues"
    run = f"{env['GITHUB_SERVER_URL']}/{env['REPO']}/actions/runs/{env['GITHUB_RUN_ID']}"
    with open(os.path.join(env["RUNNER_TEMP"], "rowstile-review.md"), encoding="utf-8") as fh:
        body = {"body": cut(fh.read(), run)}
    try:
        # one comment, updated in place: the one that starts with the review's marker, and that this token wrote
        me = account(token)
        found, page = None, 1
        while found is None:
            comments = cast(list[Comment], call("GET", f"{api}/{pr}/comments?per_page=100&page={page}", token))
            found = next((c["id"] for c in comments if ours(c, me)), None)
            if len(comments) < 100:
                break
            page += 1
        if found is None:
            call("POST", f"{api}/{pr}/comments", token, body)
        else:
            call("PATCH", f"{api}/comments/{found}", token, body)
    except urllib.error.HTTPError as e:
        if e.code == 403 and env.get("FORK") == "true":
            print(
                "::notice title=rowstile review::This pull request comes from a fork, and GitHub gives its workflow "
                "a read-only token: the review is in the run's summary, not in a comment."
            )
            return 0
        hint = (
            " The job needs permissions: {pull-requests: write} to post it (or comment: false)."
            if e.code == 403
            else ""
        )
        print(
            f"::error title=rowstile review::GitHub refused the comment ({refusal(e)}).{hint} "
            "The review is in the run's summary."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
