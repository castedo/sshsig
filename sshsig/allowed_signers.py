from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO, TYPE_CHECKING, Union

from .ssh_public_key import PublicKey


if TYPE_CHECKING:
    AllowedSignerOptions = dict[str, bool | str]


@dataclass
class AllowedSigner:
    principals: str
    options: AllowedSignerOptions | None
    key: PublicKey

    @staticmethod
    def parse(line: str) -> AllowedSigner:
        (principals, line) = lop_principals(line)
        options = None
        if detect_options(line):
            (options, line) = lop_options(line)
        pub_key = PublicKey.from_open_ssh_str(line)
        return AllowedSigner(principals, options, pub_key)


def lop_principals(line: str) -> tuple[str, str]:
    """Return (principals, rest_of_line)."""

    if line[0] == '"':
        (principals, _, line) = line[1:].partition('"')
        if not line:
            msg = "No matching double quote character for line ('{}')."
            raise SyntaxError(msg.format(line))
        return (principals, line.lstrip())
    parts = line.split(maxsplit=1)
    if len(parts) < 2:
        raise SyntaxError(f"Invalid line ('{line}').")
    return (parts[0], parts[1])


def detect_options(line: str) -> bool:
    start = line.split(maxsplit=1)[0]
    return "=" in start or "," in start or start.lower() == "cert-authority"


def lop_options(line: str) -> tuple[AllowedSignerOptions, str]:
    """Return (options, rest_of_line)."""

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
    raise SyntaxError(f"Invalid option ('{line}').")


def lop_flag(options: AllowedSignerOptions, line: str, opt_name: str) -> str | None:
    i = len(opt_name)
    if line[:i].lower() != opt_name:
        return None
    options[opt_name] = True
    if line[i : i + 1] == ",":
        i += 1
    return line[i:]


def lop_option(
    options: AllowedSignerOptions, line: str, opt_name: str
) -> str | None:
    i = len(opt_name)
    if line[:i].lower() != opt_name:
        return None
    if opt_name in options:
        raise SyntaxError(f"Multiple '{opt_name}' clauses ('{line}')")
    if line[i : i + 2] != '="':
        raise SyntaxError(f"Option '{opt_name}' missing '=\"' ('{line}')")
    (value, _, line) = line[i + 2 :].partition('"')
    if not line:
        raise SyntaxError(f"No matching quote for option '{opt_name}' ('{line}')")
    options[opt_name] = value
    return line[1:] if line[0] == "," else line


def load_allowed_signers_file(file: Union[TextIO, Path]) -> Iterable[AllowedSigner]:
    """Read public keys in "allowed signers" format per ssh-keygen."""

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
            raise SyntaxError(f"Form feed character not supported: ('{line}').")
        if "\v" in line:
            raise SyntaxError(f"Vertical tab character not supported: ('{line}').")
        line = line.strip("\n\r")
        if line and line[0] not in ["#", "\0"]:
            ret.append(AllowedSigner.parse(line))
    return ret


def for_git_allowed_keys(allowed_signers: Iterable[AllowedSigner]) -> Iterable[PublicKey]:
    """Convert a list of ssh-keygen "allowed signers" entries in "for-git" sub-format.

    In the "for-git" sub-format, only the "*" value is accepted in the principles field.
    The only allowed signers option accepted is 'namespaces="git"'.
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
        ret.append(allowed.key)
    return ret


def load_for_git_allowed_signers_file(file: Union[TextIO, Path]) -> Iterable[PublicKey]:
    return for_git_allowed_keys(load_allowed_signers_file(file))
