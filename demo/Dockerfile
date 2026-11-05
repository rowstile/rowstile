# The recorder for demo.tape: VHS, with python3 (the command runs in it: 3.11 or newer, Debian's is) and git
# (rowstile review reads the base branch from it). VHS's image has python3 only as what ffmpeg or chromium pulls in.
FROM ghcr.io/charmbracelet/vhs:v0.12.1@sha256:ea49a6a1c529be83153e88321892b5585964418f0b9055e8c1e0d732194234a3
RUN apt-get update && apt-get install -y --no-install-recommends python3 git && rm -rf /var/lib/apt/lists/*
