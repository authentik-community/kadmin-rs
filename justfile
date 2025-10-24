# List available commands
default:
  just --list

# Auto format code
lint-fix:
  cargo fmt
  black .
  ruff check --fix .
[private]
ci-lint-rustfmt:
  cargo fmt --check
[private]
ci-lint-black:
  black --check .
[private]
ci-lint-ruff:
  ruff check .

# Lint code
lint-rust:
  cargo clippy --package kadmin
  cargo clippy --package kadmin --features log
  cargo clippy --package kadmin --features python
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
  cargo build --package kadmin
  cargo build --package kadmin --features log
  cargo build --package kadmin --features python
  RUSTFLAGS="-Awarnings" cargo build --package kadmin --no-default-features --features mit_client
  RUSTFLAGS="-Awarnings" cargo build --package kadmin --no-default-features --features mit_server
  RUSTFLAGS="-Awarnings" cargo build --package kadmin --no-default-features --features heimdal_client
  RUSTFLAGS="-Awarnings" cargo build --package kadmin --no-default-features --features heimdal_server
  RUSTFLAGS="-Awarnings" cargo build --package kadmin --no-default-features --features mit_client,mit_server
  RUSTFLAGS="-Awarnings" cargo build --package kadmin --no-default-features --features heimdal_client,heimdal_server
  RUSTFLAGS="-Awarnings" cargo build --package kadmin --no-default-features --features mit_client,python
  RUSTFLAGS="-Awarnings" cargo build --package kadmin --no-default-features --features mit_server,python
  RUSTFLAGS="-Awarnings" cargo build --package kadmin --no-default-features --features heimdal_client,python
  RUSTFLAGS="-Awarnings" cargo build --package kadmin --no-default-features --features heimdal_server,python
  RUSTFLAGS="-Awarnings" cargo build --package kadmin --no-default-features --features mit_client,mit_server,python
  RUSTFLAGS="-Awarnings" cargo build --package kadmin --no-default-features --features heimdal_client,heimdal_server,python
[private]
ci-build-deps:
  sudo apt-get remove -y --purge man-db
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends build-essential pkg-config krb5-multidev heimdal-multidev python3-dev
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

alias t := test-rust
# Test rust code
test-rust:
  cargo test --package kadmin
  cargo test --package kadmin --no-default-features --features local
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
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="valgrind --error-exitcode=1 --suppressions=tests/valgrind.supp -s --leak-check=full" \
    cargo test --package kadmin
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="valgrind --error-exitcode=1 --suppressions=tests/valgrind.supp -s --leak-check=full" \
    cargo test --package kadmin --no-default-features --features local
[private]
ci-test-sanity: ci-test-deps-mit
  just test-sanity

_test-python:
  python -m unittest python/tests/test_*.py
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

docs-rust:
  cargo doc

# Generate the Python docs
docs-python:
  cd python/docs && sphinx-build -M html . _build

# Cleanup rust build directory
clean-rust:
  rm -rf target

# Cleanup python wheel builds
clean-python:
  pip uninstall -y python-kadmin-rs
  rm -rf dist wheelhouse

# Cleanup all
clean: clean-rust clean-python
