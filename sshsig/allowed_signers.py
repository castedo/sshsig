# (c) 2024 E. Castedo Ellerman <castedo@castedo.com>
# Released under the MIT License (https://spdx.org/licenses/MIT)

"""Parsing of the ssh-keygen allowed signers format."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from .ssh_public_key import PublicKey


if TYPE_CHECKING:
    AllowedSignerOptions = dict[str, str]


@dataclass
class AllowedSigner:
    principals: str
    options: AllowedSignerOptions | None
    key_type: str
    base64_key: str
    comment: str | None = None  # "patterned after" sshd authorized keys file format

    @staticmethod
    def parse(line: str) -> AllowedSigner:
        """Parse a line of an ssh-keygen "allowed signers" file.

        Raises:
            ValueError: If the line is not properly formatted.
            NotImplementedError: If the public key algorithm is not supported.
        """
        (principals, line) = lop_principals(line)
        options = None
        if detect_options(line):
            (options, line) = lop_options(line)
        parts = line.split(maxsplit=2)
        if len(parts) < 2:
            msg = "Not space-separated OpenSSH format public key ('{}')."
            raise ValueError(msg.format(line))
        return AllowedSigner(principals, options, *parts)


def lop_principals(line: str) -> tuple[str, str]:
    """Return (principals, rest_of_line)."""

    if line[0] == '"':
        (principals, _, line) = line[1:].partition('"')
        if not line:
            msg = "No matching double quote character for line ('{}')."
            raise ValueError(msg.format(line))
        return (principals, line.lstrip())
    parts = line.split(maxsplit=1)
    if len(parts) < 2:
        raise ValueError(f"Invalid line ('{line}').")
    return (parts[0], parts[1])


def detect_options(line: str) -> bool:
    start = line.split(maxsplit=1)[0]
    return "=" in start or "," in start or start.lower() == "cert-authority"


def lop_options(line: str) -> tuple[AllowedSignerOptions, str]:
    """Return (options, rest_of_line).

    Raises:
        ValueError
    """
    options: AllowedSignerOptions = dict()
    while line and not line[0].isspace():
        line = lop_one_option(options, line)
    return (options, line)


def lop_one_option(options: AllowedSignerOptions, line: str) -> str:
    if lopped := lop_flag(options, line, "cert-authority"):
        return lopped
    if lopped := lop_option(options, line, "namespaces"):
        return lopped
    if lopped := lop_option(options, line, "valid-after"):
        return lopped
    if lopped := lop_option(options, line, "valid-before"):
        return lopped
    raise ValueError(f"Invalid option ('{line}').")


def lop_flag(options: AllowedSignerOptions, line: str, opt_name: str) -> str | None:
    i = len(opt_name)
    if line[:i].lower() != opt_name:
        return None
    options[opt_name] = ""
    if line[i : i + 1] == ",":
        i += 1
    return line[i:]


def lop_option(options: AllowedSignerOptions, line: str, opt_name: str) -> str | None:
    i = len(opt_name)
    if line[:i].lower() != opt_name:
        return None
    if opt_name in options:
        raise ValueError(f"Multiple '{opt_name}' clauses ('{line}')")
    if line[i : i + 2] != '="':
        raise ValueError(f"Option '{opt_name}' missing '=\"' ('{line}')")
    (value, _, line) = line[i + 2 :].partition('"')
    if not line:
        raise ValueError(f"No matching quote for option '{opt_name}' ('{line}')")
    options[opt_name] = value
    return line[1:] if line[0] == "," else line


def load_allowed_signers_file(file: TextIO | Path) -> Iterable[AllowedSigner]:
    """Read public keys in "allowed signers" format per ssh-keygen.

    Raises:
        ValueError: If the file is not properly formatted.
    """
    # The intention of this implementation is to reproduce the behaviour of the
    # parse_principals_key_and_options function of the following sshsig.c file:
    # https://archive.softwareheritage.org/
    # swh:1:cnt:470b286a3a982875a48a5262b7057c4710b17fed

    if isinstance(file, Path):
        with open(file, encoding="ascii") as f:
            return load_allowed_signers_file(f)
    ret = list()
    for line in file.readlines():
        if "\f" in line:
            raise ValueError(f"Form feed character not supported: ('{line}').")
        if "\v" in line:
            raise ValueError(f"Vertical tab character not supported: ('{line}').")
        line = line.strip("\n\r")
        if line and line[0] not in ["#", "\0"]:
            ret.append(AllowedSigner.parse(line))
    return ret


def for_git_allowed_keys(
    allowed_signers: Iterable[AllowedSigner],
) -> Iterable[PublicKey]:
    """Convert ssh-keygen "allowed signers" entries to "just-a-list-for-git" sub-format.

    In the "just-a-list-for-git" sub-format, only the "*" value is accepted in
    the principles field. The only allowed signers option accepted is 'namespaces="git"'.

    Raises:
        ValueError: If any ssh-keygen "allowed signers" feature is used that is
            not valid in the "just-a-list-for-git" sub-format.
        NotImplementedError: If a public key algorithm is not supported.
    """
    ret = list()
    for allowed in allowed_signers:
        if allowed.principals != "*":
            raise ValueError("Only solitary wildcard principal pattern supported.")
        options = allowed.options or dict()
        only_namespaces = options.get("namespaces")
        if only_namespaces is not None and only_namespaces != "git":
            raise ValueError('Only namespaces="git" is supported.')
        if "cert-authority" in options:
            raise ValueError("Certificate keys not supported.")
        if "valid-before" in options or "valid-after" in options:
            raise ValueError("Allowed signer validation dates not supported.")
        s = " ".join((allowed.key_type, allowed.base64_key))
        ret.append(PublicKey.from_openssh_str(s))
    return ret


def load_for_git_allowed_signers_file(file: TextIO | Path) -> Iterable[PublicKey]:
    return for_git_allowed_keys(load_allowed_signers_file(file))


def save_for_git_allowed_signers_file(
    src: Iterable[PublicKey], out: Path | TextIO
) -> None:
    """Save keys for git to "allowed signers" format per ssh-keygen."""

    if isinstance(out, Path):
        with open(out, 'w') as f:
            save_for_git_allowed_signers_file(src, f)
    else:
        for key in src:
            out.write('* namespaces="git" {}\n'.format(key.openssh_str()))
