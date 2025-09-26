#!/usr/bin/env -S just --justfile

default:
    just --list

test-runtime:
    python3 -m unittest discover -t . -s tests --buffer

test: && test-runtime
    ruff check sshsig || true
    mypy --strict sshsig
    cd tests && mypy --ignore-missing-imports .  # cd for separate mypy cache+config

integration-test:
    integration/test-all

build-docs:
    mkdocs build --strict --verbose

check: test
check-runtime: test-runtime

clean:
    rm -rf dist
    rm -rf build
    rm -rf *.egg-info
    rm -f sshsig/_version.py
    rm -rf site
