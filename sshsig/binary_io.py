# (c) 2018 Mantas Mikulėnas <grawity@gmail.com>
# (c) 2024 E. Castedo Ellerman <castedo@castedo.com>
# Released under the MIT License (https://spdx.org/licenses/MIT)

from __future__ import annotations

import io
import struct
from typing import Any, BinaryIO, TYPE_CHECKING, cast


if TYPE_CHECKING:
    BytesLike = bytes | bytearray | memoryview


class SshReader:
    def __init__(self, ins: BinaryIO | BytesLike):
        if isinstance(ins, (bytes, bytearray, memoryview)):
            ins = io.BytesIO(ins)
        self.input_fh = ins

    @staticmethod
    def from_bytes(buf: BytesLike) -> SshReader:
        return SshReader(buf)

    def read(self, length: int = -1) -> bytes:
        buf = self.input_fh.read(length)
        if (not buf) and (length is not None) and (length != 0):
            raise ValueError("Unexpected end of input.")
        return buf

    def read_byte(self) -> int:
        return cast(int, self._read_and_unpack(1, "!B"))

    def read_uint32(self) -> int:
        return cast(int, self._read_and_unpack(4, "!L"))

    def read_bool(self) -> bool:
        return cast(bool, self._read_and_unpack(1, "!?"))

    def read_string(self) -> bytes:
        length = self.read_uint32()
        return self.read(length)

    def read_string_pkt(self) -> SshReader:
        return SshReader(self.read_string())

    def read_mpint(self) -> int:
        buf = self.read_string()
        return int.from_bytes(buf, byteorder="big", signed=False)

    def _read_and_unpack(self, length: int, frmt: str) -> Any:
        try:
            return struct.unpack(frmt, self.read(length))[0]
        except struct.error as ex:
            raise ValueError from ex


class SshWriter:
    def __init__(self, output_fh: io.BytesIO):
        self.output_fh = output_fh

    def write(self, b: BytesLike) -> int:
        return self.output_fh.write(b)

    def flush(self) -> None:
        self.output_fh.flush()

    def write_byte(self, val: int) -> int:
        buf = struct.pack("!B", val)
        return self.write(buf)

    def write_uint32(self, val: int) -> int:
        buf = struct.pack("!L", val)
        return self.write(buf)

    def write_bool(self, val: bool) -> int:
        buf = struct.pack("!?", val)
        return self.write(buf)

    def write_string(self, val: BytesLike) -> int:
        buf = struct.pack("!L", len(val)) + val
        return self.write(buf)

    def write_mpint(self, val: int) -> int:
        length = val.bit_length()
        if length & 0xFF:
            length |= 0xFF
            length += 1
        length >>= 8
        buf = val.to_bytes(length, "big", signed=False)
        return self.write_string(buf)
