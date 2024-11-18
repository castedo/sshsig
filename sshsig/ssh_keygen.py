from __future__ import annotations

import argparse
import io
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import BinaryIO, cast
from warnings import warn

from .allowed_signers import AllowedSigner, load_allowed_signers_file
from .ssh_public_key import InvalidSignature, PublicKey
from .sshsig import (
    SshsigSignature,
    sshsig_verify,
    ssh_keygen_check_novalidate,
)


def check_allowed_key(
    allowed: AllowedSigner, pub_key: PublicKey, principal: str, namespace: str
) -> bool:
    if allowed.principals != "*":
        msg = "Only solitary wildcard principal pattern supported."
        raise NotImplementedError(msg)
    options = allowed.options or dict()
    if "cert-authority" in options:
        warn("Certificate keys not supported in this implementation.")
        return False
    if "valid-before" in options or "valid-after" in options:
        raise NotImplementedError("Allowed signer validation dates not implemented.")
    if allowed.key != pub_key:
        return False
    if only_namespaces := options.get("namespaces"):
        if namespace not in cast(list[str], only_namespaces):
            return False
    return True


def verify(
    msg: bytes | BinaryIO,
    allowed_signers: Iterable[AllowedSigner],
    signer_identity: str,
    namespace: str,
    armored_signature: str,
) -> bool:
    msg_file = io.BytesIO(msg) if isinstance(msg, bytes) else msg
    try:
        sshsig_outer = SshsigSignature.from_armored(armored_signature)
        pub_key = sshsig_verify(sshsig_outer, msg_file, namespace)
        for allowed in allowed_signers:
            if check_allowed_key(allowed, pub_key, signer_identity, namespace):
                return True
        return False
    except InvalidSignature:
        return False


def cli_subcmd_verify(
    msg_in: BinaryIO,
    allowed_signers_file: Path,
    signer_identity: str,
    namespace: str,
    signature_file: Path,
) -> int:
    allowed = load_allowed_signers_file(allowed_signers_file)
    with open(signature_file) as f:
        armored_signature = f.read()
    good = verify(msg_in, allowed, signer_identity, namespace, armored_signature)
    return 0 if good else 255


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
    verify_parser.add_argument("-I", dest='signer_identity', required=True)
    verify_parser.add_argument("-n", dest='namespace', required=True)
    verify_parser.add_argument("-s", dest='signature_file', type=Path, required=True)
    verify_parser.add_argument("-r", dest='revocation_file', help="not implemented")

    noms = parser.parse_args(args)

    if noms.option:
        print("ssh-keygen -O option is not implemented.", file=sys.stderr)
        return 2

    if noms.subcmd == "check-novalidate":
        try:
            with open(noms.signature_file) as f:
                ssh_keygen_check_novalidate(stdin, noms.namespace, f.read())
            return 0
        except InvalidSignature as ex:
            print(ex, file=sys.stderr)
            return 255
    if noms.subcmd == "verify":
        if noms.revocation_file:
            print("ssh-keygen verify -r option is not implemented.", file=sys.stderr)
            return 2
        return cli_subcmd_verify(
            stdin,
            noms.allowed_signers_file,
            noms.signer_identity,
            noms.namespace,
            noms.signature_file,
        )
    errmsg = "Only verify and check-novalidate subcommands are supported."
    print(errmsg, file=sys.stderr)
    return 2


if __name__ == "__main__":
    exit(main(sys.stdin.buffer))
