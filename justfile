# List available commands
default:
  just --list

# Auto format code
lint-fix:
  cargo fmt
  black python-kadmin-rs
  ruff check --fix python-kadmin-rs
ci-lint-rustfmt:
  cargo fmt --check
ci-lint-black:
  black --check python-kadmin-rs
ci-lint-ruff:
  ruff check python-kadmin-rs
ci-lint-machete:
  cargo machete

# Lint code
lint:
  cd kadmin-sys && cargo clippy --features client
  cd kadmin-sys && cargo clippy --features server
  cd kadmin && cargo clippy
  cd kadmin && cargo clippy --no-default-features --features local
  cd python-kadmin-rs && cargo clippy
  cd python-kadmin-rs && cargo clippy --no-default-features --features local
ci-lint-clippy:
  RUSTFLAGS="-Dwarnings" just lint

alias l := lint-all
# Lint and auto format
lint-all: lint-fix lint

alias b := build-rust
# Build all rust crates
build-rust:
  cd kadmin-sys && cargo build --features client
  cd kadmin-sys && cargo build --features server
  cd kadmin && cargo build
  cd kadmin && cargo build --no-default-features --features local
  cd python-kadmin-rs && cargo build
  cd python-kadmin-rs && cargo build --no-default-features --features local
ci-build-deps:
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends krb5-multidev
ci-build-rust:
  RUSTFLAGS="-Dwarnings" just build

# Build python wheel
build-python: ci-build-deps
  python -m build
ci-build-python: build-python

# Build rust crates and python wheel
build: build-rust build-python

# Build Python wheels for all supported platforms
build-wheels:
  cibuildwheel
ci-build-wheels: ci-build-deps build-wheels

# Test kadmin-sys crate
test-kadmin-sys:
  cd kadmin-sys && cargo test --features client
  cd kadmin-sys && cargo test --features server

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
ci-test-deps:
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends valgrind libkrb5-dev krb5-kdc krb5-user krb5-admin-server
ci-test-rust: ci-test-deps
  RUSTFLAGS="-Dwarnings" just test-rust

alias tm := test-mem
# Test kadmin with valgrind for memory leaks
test-mem:
  cd kadmin && \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="valgrind --error-exitcode=1 --suppressions=tests/valgrind.supp -s --leak-check=full" \
    cargo test
  cd kadmin && \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="valgrind --error-exitcode=1 --suppressions=tests/valgrind.supp -s --leak-check=full" \
    cargo test --no-default-features --features local
ci-test-mem: ci-test-deps
  just test-mem

# Test python bindings
test-python: install-python
  python -m unittest python-kadmin-rs/tests/test_*.py
  stubtest kadmin kadmin_local
ci-test-python: test-python

# Test rust crates and python bindings
test-all: test-rust test-mem test-python
alias ta := test-all

# Build and install wheel
install-python: clean-python build
  pip install --force-reinstall dist/python_kadmin_rs-*.whl

# Cleanup rust build directory
clean-rust:
  rm -rf target

# Cleanup python wheel builds
clean-python:
  pip uninstall -y python-kadmin-rs
  rm -rf dist wheelhouse

# Cleanup all
clean: clean-rust clean-python
