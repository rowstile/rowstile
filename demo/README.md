# The demo

`demo.gif`, at the top of the repository's README: a policy, its tests, a one-word change and what the review
says of it, a refusal that says why, and what would grant it. About eighty seconds.

It is recorded, not drawn. `record.sh` starts a Postgres container with the app of
[getting started](../docs/getting-started.md) (its tables, its rows, and one share), makes a folder with that
guide's policy and tests as a git repository, and runs `demo.tape` in a terminal recorder
([VHS](https://github.com/charmbracelet/vhs)) in a container: the tape types the commands of this checkout,
and what the recording shows is what they printed.

    demo/record.sh        # writes demo/out/demo.gif and demo/out/demo.mp4

Look at the result, then copy `demo/out/demo.gif` over `demo/demo.gif` and commit it. The MP4 is the same
recording as a video file, for where a GIF isn't taken; it isn't kept in the repository.

Record it again when what the commands print changes, and at each release at least ([RELEASING.md](../RELEASING.md)):
a recording that shows last year's output is worse than none.

| file | what |
|---|---|
| `demo.tape` | the script: what is typed, and how long each answer stays on screen |
| `record.sh` | the containers around it: the recorder, Postgres, the project |
| `files.py` | takes the tables, the policy and the tests out of the guide, so the demo and the guide can't drift |
| `Dockerfile` | the recorder's image: VHS, with git (the review reads the base branch from it) |

Needs Docker, bash and Python. The recorder's image is 3 GB the first time.
