from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import BinaryIO

from .allowed_signers import load_for_git_allowed_signers_file
from .sshsig import InvalidSignature, check_signature, verify


def cli_subcmd_check_novalidate(
    msg_in: BinaryIO,
    signature_file: Path,
    namespace: str,
) -> int:
    try:
        with open(signature_file) as f:
            check_signature(msg_in, f.read(), namespace)
        return 0
    except InvalidSignature as ex:
        print(ex, file=sys.stderr)
        return 255


def cli_subcmd_verify(
    msg_in: BinaryIO,
    signature_file: Path,
    allowed_signers_file: Path,
) -> int:
    allowed = load_for_git_allowed_signers_file(allowed_signers_file)
    try:
        with open(signature_file) as f:
            verify(msg_in, f.read(), allowed, "git")
        return 0
    except InvalidSignature as ex:
        print(ex, file=sys.stderr)
        return 255


def main(stdin: BinaryIO, args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Test reimplementation of ssh-keygen -Y"
    )
    parser.add_argument("-Y", action="store_true", required=True)
    subparsers = parser.add_subparsers(dest="subcmd", required=True)

    check_parser = subparsers.add_parser(
        "check-novalidate", help="Check signature has valid structure."
    )
    check_parser.add_argument("-O", dest="option", help="not implemented")
    check_parser.add_argument("-n", dest="namespace", required=True)
    check_parser.add_argument("-s", dest="signature_file", type=Path, required=True)

    verify_parser = subparsers.add_parser("verify", help="verify a signature")
    verify_parser.add_argument("-O", dest='option', help="not implemented")
    verify_parser.add_argument(
        "-f", dest='allowed_signers_file', type=Path, required=True
    )
    verify_parser.add_argument("-I", dest='signer_identity')
    verify_parser.add_argument("-n", dest='namespace', required=True)
    verify_parser.add_argument("-s", dest='signature_file', type=Path, required=True)
    verify_parser.add_argument("-r", dest='revocation_file', help="not implemented")

    noms = parser.parse_args(args)

    if noms.option:
        print("ssh-keygen -O option is not implemented.", file=sys.stderr)
        return 2

    if noms.subcmd == "check-novalidate":
        return cli_subcmd_check_novalidate(stdin, noms.signature_file, noms.namespace)
    if noms.subcmd == "verify":
        if noms.namespace != "git":
            msg = 'Only namespace "git" supported by verify in this implementation.'
            print(msg, file=sys.stderr)
            return 2
        if noms.revocation_file:
            print("ssh-keygen verify -r option is not implemented.", file=sys.stderr)
            return 2
        return cli_subcmd_verify(stdin, noms.signature_file, noms.allowed_signers_file)
    errmsg = "Only verify and check-novalidate subcommands are supported."
    print(errmsg, file=sys.stderr)
    return 2


if __name__ == "__main__":
    exit(main(sys.stdin.buffer))
