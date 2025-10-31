# List available commands
default:
  just --list

# Auto format code
lint-fix:
  cargo fmt
  uv run black .
  uv run ruff check --fix .
[private]
ci-lint-rustfmt:
  cargo fmt --check
[private]
ci-lint-black:
  uv run black --check .
[private]
ci-lint-ruff:
  uv run ruff check .

# Lint code
lint-rust:
  cargo clippy
  cargo clippy --features log
  uv run cargo clippy --features python
[private]
ci-lint-clippy: ci-build-deps
  RUSTFLAGS="-Dwarnings" just lint-rust

# Mypy types checking
lint-mypy: install-python
  uv run stubtest kadmin
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
  cargo build
  cargo build --features log
  uv run cargo build --features python
  RUSTFLAGS="-Awarnings" cargo build --no-default-features --features mit_client
  RUSTFLAGS="-Awarnings" cargo build --no-default-features --features mit_server
  RUSTFLAGS="-Awarnings" cargo build --no-default-features --features heimdal_client
  RUSTFLAGS="-Awarnings" cargo build --no-default-features --features heimdal_server
  RUSTFLAGS="-Awarnings" cargo build --no-default-features --features mit_client,mit_server
  RUSTFLAGS="-Awarnings" cargo build --no-default-features --features heimdal_client,heimdal_server
  RUSTFLAGS="-Awarnings" uv run cargo build --no-default-features --features mit_client,python
  RUSTFLAGS="-Awarnings" uv run cargo build --no-default-features --features mit_server,python
  RUSTFLAGS="-Awarnings" uv run cargo build --no-default-features --features heimdal_client,python
  RUSTFLAGS="-Awarnings" uv run cargo build --no-default-features --features heimdal_server,python
  RUSTFLAGS="-Awarnings" uv run cargo build --no-default-features --features mit_client,mit_server,python
  RUSTFLAGS="-Awarnings" uv run cargo build --no-default-features --features heimdal_client,heimdal_server,python
[private]
ci-build-deps:
  sudo apt-get remove -y --purge man-db
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends build-essential pkg-config krb5-multidev libkrb5-dev heimdal-multidev libclang-dev python3-dev
[private]
ci-build-rust: ci-build-deps
  RUSTFLAGS="-Dwarnings" just build-rust

# Build python wheel
build-python:
  uv run maturin build
[private]
ci-build-python: ci-build-deps build-python
[private]
ci-build-python-sdist:
  uv build --sdist

# Build rust crates and python wheel
build: build-rust build-python

alias t := test-rust-mit
# Test rust code, only MIT variants
test-rust-mit:
  uv run cargo test --no-default-features --features mit_client,mit_server,log -- --nocapture
# Test rust code, only Heimdal variants
test-rust-heimdal:
  uv run cargo test --no-default-features --features heimdal_client,heimdal_server,log -- --nocapture
[private]
ci-test-deps:
  sudo apt-get install -y --no-install-recommends valgrind
[private]
ci-test-deps-mit: ci-build-deps ci-test-deps
  sudo apt-get install -y --no-install-recommends krb5-kdc krb5-user krb5-admin-server
[private]
ci-test-deps-heimdal: ci-build-deps ci-test-deps
  sudo apt-get install -y --no-install-recommends heimdal-clients heimdal-kdc
[private]
ci-test-rust-mit: ci-test-deps-mit
  RUSTFLAGS="-Dwarnings" just test-rust-mit
[private]
ci-test-rust-heimdal: ci-test-deps-heimdal
  RUSTFLAGS="-Dwarnings" just test-rust-heimdal

alias ts := test-sanity-mit
# Test kadmin with valgrind for memory leaks, only MIT variants
test-sanity-mit:
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="valgrind --error-exitcode=1 --suppressions=tests/valgrind.supp -s --leak-check=full" just test-rust-mit
# Test kadmin with valgrind for memory leaks, only Heimdal variants
test-sanity-heimdal:
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="valgrind --error-exitcode=1 --suppressions=tests/valgrind.supp -s --leak-check=full" just test-rust-heimdal
[private]
ci-test-sanity-mit: ci-test-deps-mit
  just test-sanity-mit
[private]
ci-test-sanity-heimdal: ci-test-deps-heimdal
  just test-sanity-heimdal

_test-python:
  uv run python -m unittest python/tests/test_*.py
# Test python bindings
test-python: install-python _test-python
[private]
ci-test-deps-h5l: ci-test-deps
  sudo apt-get install -y --no-install-recommends libkrb5-3 libkadm5clnt-mit12 libkadm5srv-mit12 heimdal-dev heimdal-servers heimdal-kdc
[private]
ci-test-python-mit: ci-test-deps-mit _install-python _test-python
[private]
ci-test-python-h5l: ci-test-deps-h5l _install-python _test-python

# Test rust crates and python bindings
test-all: test-rust-mit test-sanity test-python
alias ta := test-all

_install-python:
  uv pip install --force-reinstall target/wheels/python_kadmin_rs-*.whl
# Build and install wheel
install-python: clean-python build-python _install-python

docs-rust:
  cargo doc

# Generate the Python docs
docs-python:
  cd python/docs && uv run sphinx-build -M html . _build

# Cleanup rust build directory
clean-rust:
  rm -rf target

# Cleanup python wheel builds
clean-python:
  uv pip uninstall python-kadmin-rs
  rm -rf dist target/wheels wheelhouse

# Cleanup all
clean: clean-rust clean-python
