#!/usr/bin/env -S just --justfile

default:
    just --list

test-runtime:
    pytest tests

test: && test-runtime
    ruff check sshsig || true
    mypy --strict sshsig
    cd tests && mypy --ignore-missing-imports .  # cd for separate mypy cache+config

check-with-unittest:
    python3 -m unittest discover -t . -s tests --buffer

check: test
check-runtime: test-runtime
