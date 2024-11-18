#!/usr/bin/env -S just --justfile

default:
    just --list

check-runtime:
    pytest tests -s

check: && check-runtime
    ruff check sshsig
    mypy --strict sshsig
    mypy tests

check-with-unittest:
    python3 -m unittest discover -t . -s tests --buffer
