# (c) 2024 E. Castedo Ellerman <castedo@castedo.com>
# Released under the MIT License (https://spdx.org/licenses/MIT)

from typing import TypeVar

ExceptionT = TypeVar('ExceptionT', bound='Exception')
NonExceptionT = TypeVar('NonExceptionT')


def excast(ret: NonExceptionT | Exception) -> NonExceptionT:
    if isinstance(ret, Exception):
        raise ret
    return ret


def error_chain(ret: ExceptionT, cause: Exception) -> ExceptionT:
    ret.__cause__ = cause
    return ret
