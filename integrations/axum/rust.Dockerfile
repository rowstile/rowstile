# The Axum suite's Rust side (test.sh builds it, and runs cargo in it: the SDK's checks, its package, the app, the
# checks and their coverage): the official Rust image pinned in ../images/Dockerfile (by digest, which Dependabot
# moves there), with what the checks need. Clippy and rustfmt; LLVM's tools and cargo-llvm-cov (its release's Linux
# x86-64 binary, checked against its hash), which measure what the checks run of the SDK; python3 for the rowstile
# command (checks 9 and 14 run rowstile client and rowstile migrate).
#   docker build -t rowstile-axum --build-arg RUST_IMAGE=<rust image> -f integrations/axum/rust.Dockerfile integrations/axum
ARG RUST_IMAGE
FROM ${RUST_IMAGE}
ARG LLVM_COV=v0.9.1
ARG LLVM_COV_SHA=b3f68e625481fed9b16444174f3fa5ebcdbde4a1878803a35eabe2dcefcdc41a
ADD --checksum=sha256:${LLVM_COV_SHA} \
  https://github.com/taiki-e/cargo-llvm-cov/releases/download/${LLVM_COV}/cargo-llvm-cov-x86_64-unknown-linux-gnu.tar.gz \
  /tmp/cargo-llvm-cov.tar.gz
RUN tar -xzf /tmp/cargo-llvm-cov.tar.gz -C /usr/local/cargo/bin && rm /tmp/cargo-llvm-cov.tar.gz \
 && rustup component add clippy rustfmt llvm-tools-preview \
 && apt-get update && apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/* \
 && chmod -R a+rwX /usr/local/cargo /usr/local/rustup
