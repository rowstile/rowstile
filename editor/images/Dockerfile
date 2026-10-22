# The toolchains editor/test.sh runs in, a stage each, pinned by digest as the other images are (Dependabot moves
# the digests: a red editors job then comes from a change in git, not from a tag pushed again overnight). Never
# built: test.sh reads each stage's image by its name.
FROM node:24-trixie@sha256:016f604a11c4c725f0a4c62e29ff11adab153d297bf97046c9bf2ddb9f1011d3 AS node
FROM rust:1@sha256:a5ab4292e80567dc92f642e2a7d63773ebd695b82b56e8f06dc8d6ecc5600b76 AS rust
