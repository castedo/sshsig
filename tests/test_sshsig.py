# (c) 2024 E. Castedo Ellerman <castedo@castedo.com>
# Released under the MIT License (https://spdx.org/licenses/MIT)
# fmt: off

from pathlib import Path
from unittest import TestCase

from sshsig import sshsig

from compat import ssh_keygen
from compat.allowed_signers import load_for_git_allowed_signers_file


TESTDATA_DIR = Path(__file__).parent.parent / "testdata"
SSHSIG_CASES = list((TESTDATA_DIR / "sshsig").iterdir())


msg_sig_pair_of_commit = (
    """\
tree fd7187a49a7b26eb36d782d34c672245b94b2e30
parent b0162c139e4ea2e4783402de26617c912eef1e19
author Castedo Ellerman <castedo@castedo.com> 1729263976 -0400
committer Castedo Ellerman <castedo@castedo.com> 1729263976 -0400

use vite-plugin-static-copy in doc example of Vite
""",
    """\
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAghB1C63jrmh3eWRXJVbrTfw9wP/
BIZf/aKPdFxBlMCq0AAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQJoJUglNVFSaWhnbCl4WImCRLUEo6ymS9WBVOqpoH4kJVgIAMmCIAq9yDOL4fGYmJ0
GsF7btQ1wFf6sbMzq9nwA=
-----END SSH SIGNATURE-----
""",
)

### The following test case produced by
### echo Hola Mundo > hola.txt
### ssh-keygen -Y sign -f test_sign_key -n git hola.txt
### using test_sign_key in ../testdata

msg_sig_pair_hola_mundo = (
    """\
Hola Mundo
""",
    """\
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgZz+kZMT7JBP0t1l1HQ0K8CduhZ
XTBP/l3sXkZMqTtAkAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQDFSdQINV271MZ5VwFecGD8oJRob5Nb04r06oVVVCflwgbDLcezjmHJQo41/H3/HXj
pQWO8AJXrx7gcPAcCFGQ0=
-----END SSH SIGNATURE-----
""",
)


### The following test case produced by
### cd ../testdata
### echo Hola Mundo > hola.txt
### chmod 600 rsa_key
### ssh-keygen -Y sign -f rsa_key -n git hola.txt

msg_sig_pair_rsa = (
    """\
Hola Mundo
""",
    """\
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAZcAAAAHc3NoLXJzYQAAAAMBAAEAAAGBAJXDk57H4TBAsZIkZpI7WS
kyBohbjgBnHNGzOA/pbCwXcYVJQmqgrBSdLv9yWD1JeL51c7ZTAuzZ5IFVe03pg/MaGKdX
5uD7qTfg268lDVrekMUQTvEnDfLRpj0nWT6QMQu2Ux69EyXtMo6dEupFe6gIJgmh/fzJxD
g8tr+YeYk67gxgI6zTNqS27UJGvOSL+aHeGfM4/XvmHnxGD0aP89ab1Aii6aS1e+ReK1Xd
oQfuyaEy9D3T80ggLYwzjpLEStaJ9HYDsDtPPugbeZJPWrdMvt9NDuw+uRCnrgb4//jonw
VxI1fG5pgjy7vD5ZD9SRU7tepebI0tnvaitDZT465e9Bcc5R5ReSU0KGCgCH6NTw+nu8VO
d4IM/ncBym5llF2yqT2Tq26gpIDPqbATpoHrnsYCtyTiWKggWk/2Es+ibJjoUKNedv1bBP
aorffM6nqWAC3eGzXDgvIyKeiLSzNG234d+mkzqLB4hruco8L1FcYW7OW3sqWfI6aoomip
5QAAAANnaXQAAAAAAAAABnNoYTUxMgAAAZQAAAAMcnNhLXNoYTItNTEyAAABgIY1pbSqXK
FJ8/9GaFAuCkcSJ7YwW1MuidrWXqsDH4IE4j10u3LnQhGd8qKDH9dm93sP15IRuRnbJXg3
qVVFrnxS//EO8BmXHDekLo8yp11CqzYfRrboIvzMRufLdZ8Kt7d+p+jvJuDqN9WHDSyifI
D8o7X4tenND+QtELzi2aNrqaAtJYlNBQzxLrUqXSMHdDTDqwkuQaBWCHSmykxi84F9qb6q
K5ogklBOJKekyMFXxgPwu+uBXMkCo18QIlUS+J76H4hmJVsIrHOZZntfLOa1dDU8lRZmJP
wzCztwzaShx4OTASnJ/wKXtqXFvbz+asPnCqngoYO1aWDg5OzvEFG3DMUpTKRthMuYUWAB
TuWmFFLbjPQf1f9r1+/bwquZxapoKNVJfg7IYTfKFI9zKve3z3NLZ52+7eoqYaZsuzjN/a
4r4pfG9OMr60XApWaJkTO0K0RjrCKy9/bsXz5pJTCM5Tm4E3xLQW70GbTVfceDX713lnvx
8ZPva0b19v/BgA==
-----END SSH SIGNATURE-----
""",
)


msg_sig_pair_cases = [
    msg_sig_pair_of_commit,
    msg_sig_pair_hola_mundo,
    msg_sig_pair_rsa,
]


crazy_ascii = "Nobody expects the Spanish ..."
crazy_unicode = "Nobody expects 🥘💃🐂 ..."


def good_check_novalidate(message: str, signature: str, namespace: str = "git") -> bool:
    try:
        ssh_keygen.check_signature(message, signature, namespace)
        return True
    except sshsig.InvalidSignature:
        return False

class SshKeygenCheckNoValidate(TestCase):
    def test_good_msg_sig_pairs(self):
        for case in msg_sig_pair_cases:
            with self.subTest(case=case):
                (msg, sig) = case
                self.assertTrue(good_check_novalidate(msg, sig))

    def test_hola_mundo(self):
        (msg, sig) = msg_sig_pair_hola_mundo
        self.assertTrue(good_check_novalidate(msg, sig))

    def test_reject_mixed_msg_sig_pairs(self):
        (msg1, sig1) = msg_sig_pair_of_commit
        (msg2, sig2) = msg_sig_pair_hola_mundo
        self.assertFalse(good_check_novalidate(msg1, sig2))
        self.assertFalse(good_check_novalidate(msg2, sig1))

    def test_reject_subcmd_check_novalidate(self):
        (msg, sig) = msg_sig_pair_of_commit

        self.assertFalse(good_check_novalidate(msg, crazy_ascii))
        self.assertFalse(good_check_novalidate(msg, crazy_unicode))
        self.assertFalse(good_check_novalidate(crazy_ascii, sig))
        self.assertFalse(good_check_novalidate(crazy_unicode, sig))

        # the signature was signed with namespace "git"
        self.assertFalse(good_check_novalidate(msg, sig, "not-git"))


def good_verify(message: str, signers, signature: str) -> bool:
    try:
        ssh_keygen.verify(message, signature, signers)
        return True
    except sshsig.InvalidSignature:
        return False

class VerifyTests(TestCase):

    def verify(self, case):
        with open(case / "message", "rb") as f:
            msg = f.read()
        with open(case / "message.sig") as f:
            armored = f.read()
        signers = load_for_git_allowed_signers_file(case / "allowed_signers")

        self.assertTrue(good_verify(msg, signers, armored))
        bad = b"Corrupt" + msg
        self.assertFalse(good_verify(bad, signers, armored))

        nobody = load_for_git_allowed_signers_file(
            TESTDATA_DIR / "only_lost_allowed_signer"
        )
        self.assertFalse(good_verify(msg, nobody, armored))

    def test_case_0(self):
        self.verify(SSHSIG_CASES[0])


class ParseSignature(TestCase):

    def test_ascii_armor(self):
        for case in msg_sig_pair_cases:
            armored = case[1]
            with self.subTest(armored=armored):
                buf = sshsig.ssh_dearmor_sshsig(armored)
                sig = sshsig.SshsigSignature(buf)
                buf2 = sshsig.ssh_dearmor_sshsig(sig.to_armored())
                self.assertEqual(buf, buf2)
