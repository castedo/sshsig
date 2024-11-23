# (c) 2018 Mantas Mikulėnas <grawity@gmail.com>
# (c) 2024 E. Castedo Ellerman <castedo@castedo.com>
# Released under the MIT License (https://spdx.org/licenses/MIT)
# fmt: off

from __future__ import annotations

import binascii
from abc import ABC, abstractmethod
from typing import Any, ClassVar

import cryptography.exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .binary_io import SshReader, ssh_read_string_pair


class PublicKeyAlgorithm(ABC):
    supported: ClassVar[dict[str, PublicKeyAlgorithm]] = dict()

    @staticmethod
    def init_supported_algos() -> None:
        PublicKeyAlgorithm.supported = {
            "ssh-ed25519": Ed25519Algorithm(),
            "ssh-rsa": RsaAlgorithm(),
        }

    @abstractmethod
    def load_public_key(self, pkt: SshReader) -> PublicKey: ...

    @staticmethod
    def from_key_type(key_type: str) -> PublicKeyAlgorithm:
        if not PublicKeyAlgorithm.supported:
            PublicKeyAlgorithm.init_supported_algos()
        algo = PublicKeyAlgorithm.supported.get(key_type)
        if algo is None:
            msg = f"Public key algorithm not supported: {key_type}."
            raise NotImplementedError(msg)
        return algo

    @staticmethod
    def from_ssh_encoding(pkt: SshReader) -> PublicKeyAlgorithm:
        return PublicKeyAlgorithm.from_key_type(pkt.read_string().decode())


class PublicKey(ABC):

    @abstractmethod
    def verification_error(self, signature: bytes, message: bytes) -> Exception | None:
        """Verify the signature matches the message.

        Returns:
            None if the signature is verified to match the message.
            Otherwise, an exception object describing the reason the signature does
            not match the message.

        Raises:
            Possible exceptions for reasons other than the public key determining
            the signature does not match the message.
        """
        ...

    def try_verify(self, signature: bytes, message: bytes) -> None:
        """Verify the signature matches the message.

        Subclasses should override verification_error, not try_verify.

        Raises:
            An exception object describing the reason the signature does
            not match the message.
        """
        if err := self.verification_error(signature, message):
            raise err
        return None

    @abstractmethod
    def open_ssh_str(self) -> str: ...

    def __str__(self) -> str:
        return self.open_ssh_str()

    @staticmethod
    def from_open_ssh_str(line: str) -> PublicKey:
        """Create PublicKey from an OpenSSH format public key string.

        Raises:
            ValueError: If the input string is not a valid format or encoding.
            NotImplementedError: If the public key algorithm is not supported.
        """
        parts = line.split(maxsplit=2)
        if len(parts) < 2:
            msg = "Not space-separated OpenSSH format public key ('{}')."
            raise ValueError(msg.format(line))
        key_type = parts[0]
        try:
            buf = binascii.a2b_base64(parts[1])
        except binascii.Error as ex:
            raise ValueError from ex
        pkt = SshReader(buf)
        if pkt.read_string().decode() != key_type:
            raise ValueError("Improperly encoded public key.")
        algo = PublicKeyAlgorithm.from_key_type(key_type)
        return algo.load_public_key(pkt)

    @staticmethod
    def from_ssh_encoding(buf: bytes) -> PublicKey:
        pkt = SshReader(buf)
        algo = PublicKeyAlgorithm.from_ssh_encoding(pkt)
        return algo.load_public_key(pkt)


##############################################################################
# Ed25519 Public Key Algo
#
# https://tools.ietf.org/html/draft-ietf-curdle-ssh-ed25519-ed448-00#section-4

class Ed25519Algorithm(PublicKeyAlgorithm):

    def load_public_key(self, pkt: SshReader) -> PublicKey:
        return Ed25519PublicKey(pkt.read_string())

class Ed25519PublicKey(PublicKey):
    def __init__(self, raw_key: bytes):
        self._impl = ed25519.Ed25519PublicKey.from_public_bytes(raw_key)
        ## python cryptography 36.0 does not do equality properly
        ## hold on to raw key to perform correct equality function
        self._raw_key = raw_key

    def verification_error(self, signature: bytes, message: bytes) -> Exception | None:
        sig_algo, raw_signature = ssh_read_string_pair(signature)
        assert sig_algo == b"ssh-ed25519"
        try:
            self._impl.verify(raw_signature, message)
            return None
        except cryptography.exceptions.InvalidSignature as ex:
            return ex

    def open_ssh_str(self) -> str:
        return self._impl.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Ed25519PublicKey):
            return self._raw_key == other._raw_key
        return False

    def __hash__(self) -> int:
        return hash(self._raw_key)


##############################################################################
# RSA Public Key Algo
#
# https://tools.ietf.org/html/rfc4253#section-6.6

class RsaAlgorithm(PublicKeyAlgorithm):

    def load_public_key(self, pkt: SshReader) -> PublicKey:
        e = pkt.read_mpint()
        n = pkt.read_mpint()
        return RsaPublicKey(e, n)

class RsaPublicKey(PublicKey):
    def __init__(self, e: int, n: int):
        self._impl = rsa.RSAPublicNumbers(e, n).public_key()
        ## python cryptography 36.0 does not do equality properly
        ## hold on to raw numbers to perform correct equality function
        self._e = e
        self._n = n

    def verification_error(self, signature: bytes, message: bytes) -> Exception | None:
        sig_algo, raw_signature = ssh_read_string_pair(signature)
        assert sig_algo == b"rsa-sha2-512"
        try:
            self._impl.verify(raw_signature, message, padding.PKCS1v15(), hashes.SHA512())
            return None
        except cryptography.exceptions.InvalidSignature as ex:
            return ex

    def open_ssh_str(self) -> str:
        return self._impl.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, RsaPublicKey):
            return self._e == other._e and self._n == other._n
        return False

    def __hash__(self) -> int:
        return hash((self._e, self._n))
