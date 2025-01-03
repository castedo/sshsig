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

check: test
check-runtime: test-runtime
