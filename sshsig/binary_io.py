# (c) 2018 Mantas Mikulėnas <grawity@gmail.com>
# (c) 2024 E. Castedo Ellerman <castedo@castedo.com>
# Released under the MIT License (https://spdx.org/licenses/MIT)

from __future__ import annotations

import io
import struct
from collections.abc import ByteString
from typing import BinaryIO, cast


class SshReader:
    @staticmethod
    def from_bytes(buf: ByteString) -> SshReader:
        return SshReader(io.BytesIO(buf))

    def __init__(self, input_fh: BinaryIO):
        self.input_fh = input_fh

    def read(self, length: int = -1) -> bytes:
        buf = self.input_fh.read(length)
        if (not buf) and (length is not None) and (length != 0):
            raise ValueError("Unexpected end of input.")
        return buf

    def read_byte(self) -> int:
        buf = self.read(1)
        (val,) = struct.unpack("!B", buf)
        return cast(int, val)

    def read_uint32(self) -> int:
        buf = self.read(4)
        (val,) = struct.unpack("!L", buf)
        return cast(int, val)

    def read_bool(self) -> bool:
        buf = self.read(1)
        (val,) = struct.unpack("!?", buf)
        return cast(bool, val)

    def read_string(self) -> bytes:
        length = self.read_uint32()
        buf = self.read(length)
        return buf

    def read_string_pkt(self) -> SshReader:
        buf = self.read_string()
        return SshReader.from_bytes(buf)

    def read_mpint(self) -> int:
        buf = self.read_string()
        return int.from_bytes(buf, byteorder="big", signed=False)


class SshWriter:
    def __init__(self, output_fh: io.BytesIO):
        self.output_fh = output_fh

    def write(self, b: ByteString) -> int:
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

    def write_string(self, val: ByteString) -> int:
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
