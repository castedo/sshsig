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
from .unexceptional import cast_or_raise, unexceptional


class PublicKeyAlgorithm(ABC):
    supported: ClassVar[dict[str, PublicKeyAlgorithm]] = dict()

    @staticmethod
    def supported_algos() -> list[PublicKeyAlgorithm]:
        return [Ed25519Algorithm(), RsaAlgorithm()]

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def load_public_key(self, pkt: SshReader) -> PublicKey: ...

    @classmethod
    def from_name(cls, algo_name: str) -> PublicKeyAlgorithm:
        return cast_or_raise(cls.do_from_name(algo_name))

    @classmethod
    def do_from_name(cls, algo_name: str) -> PublicKeyAlgorithm | NotImplementedError:
        if not cls.supported:
            cls.supported = {a.name: a for a in cls.supported_algos()}
        algo = PublicKeyAlgorithm.supported.get(algo_name)
        if algo is None:
            msg = f"Public key algorithm not supported: {algo_name}."
            return unexceptional(NotImplementedError(msg))
        return algo


class PublicKey(ABC):

    @property
    @abstractmethod
    def algo_name(self) -> str: ...

    def verify(self, signature: bytes, message: bytes) -> None:
        """Verify the signature matches the message.

        Subclasses should override do_verify, not verify.

        Raises:
            Exception: An exception object describing the reason the signature does \
            not match the message.
        """
        return cast_or_raise(self.do_verify(signature, message))

    @abstractmethod
    def do_verify(self, signature: bytes, message: bytes) -> None | Exception:
        """Verify the signature matches the message.

        Call verify if you want an exception raised instead of returned.

        Returns:
            None if the signature is verified to match the message.
            Otherwise, an exception object describing the reason the signature does
            not match the message.

        Raises:
            Exception: Possible exceptions for reasons other than the public key \
            determining the signature does not match the message.
        """
        ...

    @abstractmethod
    def openssh_str(self) -> str: ...

    def __str__(self) -> str:
        return self.openssh_str()

    @classmethod
    def from_openssh_str(cls, line: str) -> PublicKey:
        return cast_or_raise(cls.do_from_openssh_str(line))

    @staticmethod
    def do_from_openssh_str(line: str) -> PublicKey | ValueError | NotImplementedError:
        """Create PublicKey from an OpenSSH format public key string.

        Returns:
            PublicKey: If no error.
            ValueError: If the input string is not a valid format or encoding.
            NotImplementedError: If the public key algorithm is not supported.
        """
        parts = line.split(maxsplit=2)
        if len(parts) < 2:
            msg = "Not space-separated OpenSSH format public key ('{}')."
            return unexceptional(ValueError(msg.format(line)))
        key_algo_name = parts[0]
        try:
            buf = binascii.a2b_base64(parts[1])
        except binascii.Error as ex:
            return unexceptional(ValueError(), ex)
        ret = PublicKey.do_from_ssh_encoding(buf)
        if not isinstance(ret, PublicKey):
            return ret
        if ret.algo_name != key_algo_name:
            return unexceptional(ValueError("Improperly encoded public key."))
        return ret

    @classmethod
    def from_ssh_encoding(cls, buf: bytes) -> PublicKey:
        return cast_or_raise(cls.do_from_ssh_encoding(buf))

    @staticmethod
    def do_from_ssh_encoding(
        buf: bytes,
    ) -> PublicKey | ValueError | NotImplementedError:
        try:
            pkt = SshReader(buf)
            algo_name = pkt.read_string().decode()
            algo = PublicKeyAlgorithm.do_from_name(algo_name)
            if not isinstance(algo, PublicKeyAlgorithm):
                return algo
            return algo.load_public_key(pkt)
        except ValueError as error:
            return error


##############################################################################
# Ed25519 Public Key Algo
#
# https://tools.ietf.org/html/draft-ietf-curdle-ssh-ed25519-ed448-00#section-4

class Ed25519Algorithm(PublicKeyAlgorithm):

    @property
    def name(self) -> str:
        return "ssh-ed25519"

    def load_public_key(self, pkt: SshReader) -> PublicKey:
        return Ed25519PublicKey(pkt.read_string())

class Ed25519PublicKey(PublicKey):
    def __init__(self, raw_key: bytes):
        self._impl = ed25519.Ed25519PublicKey.from_public_bytes(raw_key)
        ## python cryptography 36.0 does not do equality properly
        ## hold on to raw key to perform correct equality function
        self._raw_key = raw_key

    @property
    def algo_name(self) -> str:
        return "ssh-ed25519"

    def do_verify(self, signature: bytes, message: bytes) -> None | Exception:
        sig_algo, raw_signature = ssh_read_string_pair(signature)
        assert sig_algo == b"ssh-ed25519"
        try:
            self._impl.verify(raw_signature, message)
            return None
        except cryptography.exceptions.InvalidSignature as ex:
            return ex

    def openssh_str(self) -> str:
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

    @property
    def name(self) -> str:
        return "ssh-rsa"

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

    @property
    def algo_name(self) -> str:
        return "ssh-rsa"

    def do_verify(self, signature: bytes, message: bytes) -> None | Exception:
        sig_algo, raw_signature = ssh_read_string_pair(signature)
        if sig_algo not in [b"rsa-sha2-512", b"rsa-sha2-256"]:
            msg = f"Unsupported RSA signature hash algorithm: {sig_algo!r}"
            return unexceptional(ValueError(msg))
        hash_algo = hashes.SHA512() if sig_algo == b"rsa-sha2-512" else hashes.SHA256()
        try:
            self._impl.verify(raw_signature, message, padding.PKCS1v15(), hash_algo)
            return None
        except cryptography.exceptions.InvalidSignature as ex:
            return ex

    def openssh_str(self) -> str:
        return self._impl.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, RsaPublicKey):
            return self._e == other._e and self._n == other._n
        return False

    def __hash__(self) -> int:
        return hash((self._e, self._n))
