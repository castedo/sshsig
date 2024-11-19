import io
import subprocess
import tempfile
from pathlib import Path

from sshsig import ssh_keygen
from .test_sshsig import SshKeygenCheckNoValidate

from unittest import TestCase

TESTDATA_DIR = Path(__file__).parent.parent / "testdata"
SSHSIG_CASES = list((TESTDATA_DIR / "sshsig").iterdir())


class CompatTestSshKeygenCheckNoValidate(SshKeygenCheckNoValidate):
    def good_check_novalidate(
        self, message: str, signature: str, namespace: str = "git"
    ) -> bool:
        cmdline = ["ssh-keygen", "-Y", "check-novalidate", "-n", namespace]
        with tempfile.NamedTemporaryFile() as sig_file:
            sig_file.write(signature.encode())
            sig_file.flush()
            cmdline += ["-s", sig_file.name]
            result = subprocess.run(cmdline, input=message.encode())
            return result.returncode == 0


class SimCliCheckNoValidate(SshKeygenCheckNoValidate):

    def good_check_novalidate(
        self, message: str, signature: str, namespace: str = "git"
    ) -> bool:
        args = ["-Y", "check-novalidate", "-n", namespace]
        with tempfile.NamedTemporaryFile() as sig_file:
            sig_file.write(signature.encode())
            sig_file.flush()
            args += ["-s", sig_file.name]
            msg_in = io.BytesIO(message.encode())
            return 0 == ssh_keygen.main(msg_in, args)


class CLITests(TestCase):

    def verify(self, case):
        args = ["-Y", "verify"]
        args += ["-f", str(case / "allowed_signers")]
        args += ["-n", "git"]
        args += ["-s", str(case / "message.sig")]
        args += ["-I", '*']
        with open(case / "message", "rb") as msgin:
            self.assertEqual(0, ssh_keygen.main(msgin, args))

    def test_verify_case_0(self):
        self.verify(SSHSIG_CASES[0])
