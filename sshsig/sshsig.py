# (c) 2018 Mantas Mikulėnas <grawity@gmail.com>
# (c) 2024 E. Castedo Ellerman <castedo@castedo.com>
# Released under the MIT License (https://spdx.org/licenses/MIT)

from __future__ import annotations

import binascii
import hashlib
import io
from collections.abc import ByteString, Iterable
from typing import BinaryIO

from .binary_io import SshReader, SshWriter
from .ssh_public_key import PublicKey, PublicKeyAlgorithm, InvalidSignature


SshsigError = InvalidSignature

class UnsupportedVersion(Exception):
    pass


def ssh_enarmor_sshsig(raw: bytes) -> str:
    lines = ["-----BEGIN SSH SIGNATURE-----"]
    buf = binascii.b2a_base64(raw, newline=False).decode()
    for i in range(0, len(buf), 76):
        lines.append(buf[i : i + 76])
    lines += ["-----END SSH SIGNATURE-----", ""]
    return "\n".join(lines)


def ssh_dearmor_sshsig(buf: str) -> bytes:
    acc = ""
    match = False
    # TODO: stricter format check
    for line in buf.splitlines():
        if line == "-----BEGIN SSH SIGNATURE-----":
            match = True
        elif line == "-----END SSH SIGNATURE-----":
            break
        elif line and match:
            acc += line
    return binascii.a2b_base64(acc)


class SshsigWrapper:
    """The inner 'to-be-signed' data."""

    def __init__(
        self,
        *,
        namespace: bytes = b"",
        reserved: bytes = b"",
        hash_algo: bytes,
        hash: bytes,
    ) -> None:
        self.namespace = namespace
        self.reserved = reserved
        self.hash_algo = hash_algo
        self.hash = hash

    @staticmethod
    def from_bytes(buf: ByteString) -> SshsigWrapper:
        pkt = SshReader.from_bytes(buf)
        magic = pkt.read(6)
        if magic != b"SSHSIG":
            raise ValueError("magic preamble not found")
        return SshsigWrapper(
            namespace=pkt.read_string(),
            reserved=pkt.read_string(),
            hash_algo=pkt.read_string(),
            hash=pkt.read_string(),
        )

    def to_bytes(self) -> bytes:
        pkt = SshWriter(io.BytesIO())
        pkt.write(b"SSHSIG")
        pkt.write_string(self.namespace)
        pkt.write_string(self.reserved)
        pkt.write_string(self.hash_algo)
        pkt.write_string(self.hash)
        return pkt.output_fh.getvalue()


class SshsigSignature:
    def __init__(
        self,
        *,
        version: int = 0x01,
        public_key: bytes,
        namespace: bytes = b"",
        reserved: bytes = b"",
        hash_algo: bytes,
        signature: bytes,
    ):
        self.version = version
        self.public_key = public_key
        self.namespace = namespace
        self.reserved = reserved
        self.hash_algo = hash_algo
        self.signature = signature

    @staticmethod
    def from_bytes(buf: ByteString) -> SshsigSignature:
        pkt = SshReader.from_bytes(buf)
        magic = pkt.read(6)
        if magic != b"SSHSIG":
            raise ValueError("magic preamble not found")
        version = pkt.read_uint32()
        if version != 0x01:
            raise UnsupportedVersion(version)
        return SshsigSignature(
            version=version,
            public_key=pkt.read_string(),
            namespace=pkt.read_string(),
            reserved=pkt.read_string(),
            hash_algo=pkt.read_string(),
            signature=pkt.read_string(),
        )

    def to_bytes(self) -> bytes:
        pkt = SshWriter(io.BytesIO())
        pkt.write(b"SSHSIG")
        pkt.write_uint32(self.version)
        if self.version == 0x01:
            pkt.write_string(self.public_key)
            pkt.write_string(self.namespace)
            pkt.write_string(self.reserved)
            pkt.write_string(self.hash_algo)
            pkt.write_string(self.signature)
        else:
            raise UnsupportedVersion(self.version)
        return pkt.output_fh.getvalue()

    @staticmethod
    def from_armored(buf: str) -> SshsigSignature:
        return SshsigSignature.from_bytes(ssh_dearmor_sshsig(buf))

    def to_armored(self) -> str:
        return ssh_enarmor_sshsig(self.to_bytes())


def hash_file(msg_file: BinaryIO, hash_algo_name: str) -> bytes:
    hash_algo = hash_algo_name.lower()
    if hash_algo not in hashlib.algorithms_guaranteed:
        msg = "Signature hash algo '{}' not supported across platforms by Python."
        raise NotImplementedError(msg.format(hash_algo))
    hobj = hashlib.new(hash_algo)
    while data := msg_file.read(8192):
        hobj.update(data)
    return hobj.digest()


def sshsig_verify(
    sshsig_outer: SshsigSignature,
    msg_file: BinaryIO,
    namespace: str,
) -> PublicKey:
    # The intention of this implementation is to reproduce (approximately)
    # the behaviour of the sshsig_verify_fd function of the ssh-keygen C file:
    # sshsig.c
    # https://archive.softwareheritage.org/
    # swh:1:cnt:470b286a3a982875a48a5262b7057c4710b17fed

    _namespace = namespace.encode("ascii")
    if _namespace != sshsig_outer.namespace:
        errmsg = "Namespace of signature {} != {}"
        raise InvalidSignature(errmsg.format(sshsig_outer.namespace, _namespace))

    msg_hash = hash_file(msg_file, sshsig_outer.hash_algo.decode("ascii"))

    toverify = SshsigWrapper(
        namespace=_namespace, hash_algo=sshsig_outer.hash_algo, hash=msg_hash
    )
    sigdata = PublicKeyAlgorithm.parse_signature(sshsig_outer.signature)
    pub_key = PublicKey.from_ssh_encoding(sshsig_outer.public_key)
    pub_key.verify(sigdata, toverify.to_bytes())
    return pub_key


def check_novalidate(
    msg_in: str | bytes | BinaryIO, namespace: str, armored_signature: str
) -> PublicKey:
    """Check that a ssh-keygen signature has a valid structure.

    This function implements functionality provided by:
    ```
    ssh-keygen -Y check-novalidate -n {namespace} -s {armored_signature_file} < {msg_in}
    ```
    """

    if isinstance(msg_in, str):
        msg_in = msg_in.encode()
    msg_file = io.BytesIO(msg_in) if isinstance(msg_in, bytes) else msg_in
    try:
        sshsig_outer = SshsigSignature.from_armored(armored_signature)
    except ValueError as ex:
        raise InvalidSignature(ex)
    return sshsig_verify(sshsig_outer, msg_file, namespace)


def verify_for_git(
    msg_in: str | bytes | BinaryIO,
    allowed_signers: Iterable[PublicKey],
    armored_signature: str,
) -> None:
    """Verify a signature generated by ssh-keygen, the OpenSSH authentication key utility.

    This function implements as _SUBSET_ of functionality provided by:
    ```
    ssh-keygen -Y verify \
        -f {allowed_signers_file} \
        -I '*' \
        -n git -s {armored_signature_file} \
        < {msg_in}
    ```
    when the allowed_signers_file is in "for-git" sub-format with only lines starting:
    `* namespaces="git" ...`
    """
    pub_key = check_novalidate(msg_in, "git", armored_signature)
    for allowed_key in allowed_signers:
        if allowed_key == pub_key:
            return
    raise InvalidSignature("Signature public key not of allowed signer.")
