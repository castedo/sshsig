from io import StringIO
from pathlib import Path
from unittest import TestCase

from sshsig.allowed_signers import AllowedSigner, load_allowed_signers_file
from sshsig.ssh_public_key import PublicKey


TESTDATA_DIR = Path(__file__).parent.parent / "testdata"
SSHSIG_CASES = list((TESTDATA_DIR / "sshsig").iterdir())


key0 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJY08ynqE/VoH690nSN+MUxMzAbfNcMdUQr+5ltIskMt"
key1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIQdQut465od3lkVyVW6038PcD/wSGX/2ij3RcQZTAqt"

with open(TESTDATA_DIR / "rsa_key.pub") as f:
    rsa_key = f.read().strip()

open_ssh_keys = [key0, key1, rsa_key]


class PublicKeyParseTests(TestCase):

    def test_bad_base64(self):
        with self.assertRaises(ValueError):
            PublicKey.from_open_ssh_str("ssh-rsa AAAAB")
        with self.assertRaises(ValueError):
            PublicKey.from_open_ssh_str("ssh-rsa AAAA")

    def test_parse(self):
        for key in open_ssh_keys:
            with self.subTest(key=key):
                PublicKey.from_open_ssh_str(key)

    def test_roundtrip(self):
        for key in open_ssh_keys:
            with self.subTest(key=key):
                key_obj = PublicKey.from_open_ssh_str(key)
                s = key_obj.open_ssh_str()
                self.assertEqual(key_obj, PublicKey.from_open_ssh_str(s))


class FileCaseParseTests(TestCase):

    def test_case_0(self):
        load_allowed_signers_file(SSHSIG_CASES[0] / "allowed_signers")


# Many test cases are from the ssh-keygen test code:
# https://archive.softwareheritage.org/
# swh:1:cnt:dae03706d8f0cb09fa8f8cd28f86d06c4693f0c9


class ParseTests(TestCase):

    def test_man_page_example(self):
        # Example "ALLOWED SIGNERS" file from ssh-keygen man page. Man page source:
        # https://archive.softwareheritage.org/
        # swh:1:cnt:06f0555a4ec01caf8daed84b8409dd8cb3278740

        text = StringIO(
            f"""\
# Comments allowed at start of line
user1@example.com,user2@example.com {rsa_key}
# A certificate authority, trusted for all principals in a domain.
*@example.com cert-authority {key0}
# A key that is accepted only for file signing.
user2@example.com namespaces="file" {key1}
"""
        )
        expect = [
            AllowedSigner(
                "user1@example.com,user2@example.com",
                None,
                PublicKey.from_open_ssh_str(rsa_key),
            ),
            AllowedSigner(
                "*@example.com",
                {'cert-authority': True},
                PublicKey.from_open_ssh_str(key0),
            ),
            AllowedSigner(
                "user2@example.com",
                {'namespaces': "file"},
                PublicKey.from_open_ssh_str(key1),
            ),
        ]
        got = load_allowed_signers_file(text)
        self.assertEqual(expect, got)

    def test_no_options_and_quotes(self):
        text = StringIO(
            f"""\
foo@example.com {key0}
"foo@example.com" {key0}
"""
        )
        same = AllowedSigner(
            "foo@example.com", None, PublicKey.from_open_ssh_str(key0)
        )
        expect = [same, same]
        self.assertEqual(expect, load_allowed_signers_file(text))

    def test_space_in_quotes(self):
        text = StringIO(
            f"""\
"ssh-keygen parses this" {key0}
"""
        )
        expect = [
            AllowedSigner(
                "ssh-keygen parses this", None, PublicKey.from_open_ssh_str(key0),
            ),
        ]
        self.assertEqual(expect, load_allowed_signers_file(text))

    def test_with_comments(self):
        text = StringIO(
            f"""\
foo@bar {key1} even without options ssh-keygen will ignore the end
"""
        )
        expect = [
            AllowedSigner("foo@bar", None, PublicKey.from_open_ssh_str(key1)),
        ]
        self.assertEqual(expect, load_allowed_signers_file(text))

    def test_two_namespaces(self):
        text = StringIO(
            f"""\
foo@b.ar namespaces="git,got" {key1}
"""
        )
        expect = [
            AllowedSigner(
                "foo@b.ar",
                {'namespaces': "git,got"},
                PublicKey.from_open_ssh_str(key1)
            ),
        ]
        self.assertEqual(expect, load_allowed_signers_file(text))

    def test_dates(self):
        text = StringIO(
            f"""\
foo@b.ar valid-after="19801201",valid-before="20010201" {key0}
"""
        )
        expect = [
            AllowedSigner(
                "foo@b.ar",
                {"valid-after": "19801201", "valid-before": "20010201"},
                PublicKey.from_open_ssh_str(key0)
            ),
        ]
        self.assertEqual(expect, load_allowed_signers_file(text))
