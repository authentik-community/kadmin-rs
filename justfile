# List available commands
default:
  just --list

# Auto format code
lint-fix:
  cargo fmt
  black python-kadmin-rs
  ruff check --fix python-kadmin-rs

# Lint code
lint:
  cargo clippy

# Lint and auto format
lint-all: lint-fix lint
alias l := lint-all

# Build all rust crates
build-rust:
  cargo build
alias b := build-rust

# Build python wheel
build-python:
  python -m build

# Build rust crates and python wheel
build: build-rust build-python

# Build Python wheels for all supported platforms
build-all:
  cibuildwheel

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

# Test all rust crates
test-rust: test-kadmin-sys test-kadmin test-python-kadmin-rs
alias t := test-rust

# Test kadmin with valgrind for memory leaks
test-mem:
  cd kadmin && \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="valgrind --error-exitcode=1 --suppressions=tests/valgrind.supp -s --leak-check=full" \
    cargo test
alias tm := test-mem

# Test python bindings
test-python: install-python
  python -m unittest python-kadmin-rs/tests/test_*.py
  stubtest kadmin kadmin_local

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
