# The clean machines packaging/test.sh installs rowstile on, a stage each, pinned by digest as the other images are
# (Dependabot moves the digests: a red packaging job then comes from a change in git, not from a tag pushed again
# overnight). Never built: test.sh reads each stage's image by its name.
FROM node:24@sha256:14078204b6bb268c107ceff6d3c43f45a888105e5c2b18b14c32b3409d93a1b0 AS node
# the lowest Node the package's engines state (packaging/npm/rowstile/package.json): no other Node 22.12 exists
FROM node:22.12.0-slim@sha256:35531c52ce27b6575d69755c73e65d4468dba93a25644eed56dc12879cae9213 AS node-floor
FROM node:24-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5 AS node-slim
FROM node:24-alpine@sha256:44fce696f38ba8c987c4db89954051000bbd05ffd8d8659ba15ed4a8602e937f AS node-alpine
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f AS python
FROM python:3.11-slim@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce AS python-3.11
