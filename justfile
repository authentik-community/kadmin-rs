# List available commands
default:
  just --list

# Auto format code
lint-fix:
  cargo fmt
  black python-kadmin-rs
  ruff check --fix python-kadmin-rs
[private]
ci-lint-rustfmt:
  cargo fmt --check
[private]
ci-lint-black:
  black --check python-kadmin-rs
[private]
ci-lint-ruff:
  ruff check python-kadmin-rs

# Lint code
lint-rust:
  cd kadmin-sys && cargo clippy --features client
  cd kadmin-sys && cargo clippy --no-default-features --features server
  cd kadmin && cargo clippy
  cd kadmin && cargo clippy --no-default-features --features local
  cd python-kadmin-rs && cargo clippy
  cd python-kadmin-rs && cargo clippy --no-default-features --features local
[private]
ci-lint-clippy: ci-build-deps
  RUSTFLAGS="-Dwarnings" just lint-rust

# Mypy types checking
lint-mypy: install-python
  stubtest kadmin kadmin_local
[private]
ci-lint-mypy: ci-build-deps lint-mypy

alias l := lint
# Lint and auto format
lint: lint-fix lint-rust

alias la := lint-all
# Common lint plus mypy types checking
lint-all: lint lint-mypy

alias b := build-rust
# Build all rust crates
build-rust:
  cd kadmin-sys && cargo build --features client
  cd kadmin-sys && cargo build --no-default-features --features server
  cd kadmin && cargo build
  cd kadmin && cargo build --no-default-features --features local
  cd python-kadmin-rs && cargo build
  cd python-kadmin-rs && cargo build --no-default-features --features local
[private]
ci-build-deps:
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends libkrb5-dev krb5-multidev
[private]
ci-build-rust: ci-build-deps
  RUSTFLAGS="-Dwarnings" just build-rust

# Build python wheel
build-python:
  python -m build
[private]
ci-build-python: ci-build-deps build-python
[private]
ci-build-python-sdist:
  python -m build --sdist

# Build rust crates and python wheel
build: build-rust build-python

# Test kadmin-sys crate
test-kadmin-sys:
  cd kadmin-sys && cargo test --features client
  cd kadmin-sys && cargo test --no-default-features --features server

# Test kadmin crate
test-kadmin:
  cd kadmin && cargo test
  cd kadmin && cargo test --no-default-features --features local

test-python-kadmin-rs:
  cd python-kadmin-rs && cargo test
  cd python-kadmin-rs && cargo test --no-default-features --features local

alias t := test-rust
# Test all rust crates
test-rust: test-kadmin-sys test-kadmin test-python-kadmin-rs
[private]
ci-test-deps:
  sudo apt-get install -y --no-install-recommends valgrind
[private]
ci-test-deps-mit: ci-build-deps ci-test-deps
  sudo apt-get install -y --no-install-recommends krb5-kdc krb5-user krb5-admin-server
[private]
ci-test-rust: ci-test-deps-mit
  RUSTFLAGS="-Dwarnings" just test-rust

alias ts := test-sanity
# Test kadmin with valgrind for memory leaks
test-sanity:
  cd kadmin && \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="valgrind --error-exitcode=1 --suppressions=tests/valgrind.supp -s --leak-check=full" \
    cargo test
  cd kadmin && \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="valgrind --error-exitcode=1 --suppressions=tests/valgrind.supp -s --leak-check=full" \
    cargo test --no-default-features --features local
[private]
ci-test-sanity: ci-test-deps-mit
  just test-sanity

_test-python:
  python -m unittest python-kadmin-rs/tests/test_*.py
# Test python bindings
test-python: install-python _test-python
[private]
ci-test-deps-h5l: ci-test-deps
  sudo apt-get install -y --no-install-recommends libkrb5-3 libkadm5clnt-mit12 libkadm5srv-mit12 heimdal-dev heimdal-servers heimdal-kdc
[private]
ci-test-python-mit: ci-test-deps-mit _install-python _test-python
ci-test-python-h5l: ci-test-deps-h5l _install-python _test-python

# Test rust crates and python bindings
test-all: test-rust test-sanity test-python
alias ta := test-all

_install-python:
  pip install --force-reinstall dist/python_kadmin_rs-*.whl
# Build and install wheel
install-python: clean-python build-python _install-python

# Cleanup rust build directory
clean-rust:
  rm -rf target

# Cleanup python wheel builds
clean-python:
  pip uninstall -y python-kadmin-rs
  rm -rf dist wheelhouse

# Cleanup all
clean: clean-rust clean-python
