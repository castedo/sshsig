# Copyright (c) 2024 E. Castedo Ellerman <castedo@castedo.com>
# Released under the MIT License (https://spdx.org/licenses/MIT)
# fmt: off

from pathlib import Path

from dulwich.objects import InvalidSignature, SignatureCriterion

from sshsig import sshsig
from sshsig.allowed_signers import load_for_git_allowed_signers_file


class SshsigCheckCriterion(SignatureCriterion):
    """Checks signature using sshsig."""

    def check(self, crypto_msg: bytes, signature: bytes, verify_time: int) -> None:
        try:
            sshsig.check_signature(crypto_msg, signature.decode())
        except sshsig.InvalidSignature as ex:
            raise InvalidSignature from ex


class SshsigVerifyCriterion(SshsigCheckCriterion):
    """Verifies signature using sshsig and just-a-list-for-git allowed signers file."""

    def __init__(self, allowed_signers: Path):
        self.allowed = load_for_git_allowed_signers_file(allowed_signers)

    def check(self, crypto_msg: bytes, signature: bytes, verify_time: int) -> None:
        try:
            sshsig.verify(crypto_msg, signature.decode(), self.allowed)
        except sshsig.InvalidSignature as ex:
            raise InvalidSignature from ex


if __name__ == "__main__":
    import argparse, dulwich.repo

    parser = argparse.ArgumentParser()
    parser.add_argument("git_object", default="HEAD", nargs="?")
    parser.add_argument(
        "--allow", type=Path, help="Hidos DSGL just-a-list-for-git allowed signers file"
    )
    args = parser.parse_args()

    if args.allow is None:
        criterion = SshsigCheckCriterion()
    else:
        criterion = SshsigVerifyCriterion(args.allow)

    repo = dulwich.repo.Repo(".")
    commit = repo[args.git_object.encode()]
    print("commit", commit.id.decode())
    try:
        commit.check_signature(criterion)
        if commit.gpgsig:
            print("Valid signature")
    except InvalidSignature:
        print("Invalid Signature")
    print("Author:", commit.author.decode())
    print("\n    ", commit.message.decode())
