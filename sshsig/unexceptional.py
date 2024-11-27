# (c) 2024 E. Castedo Ellerman <castedo@castedo.com>
# Released under the MIT License (https://spdx.org/licenses/MIT)

"""Helper functions for returning and raising unexceptional exceptions.

Unexceptional exceptions are Exception objects that are returned as "normal" error
objects, with return type hints, for "normal" non-try-except execution flow in some,
but not necessarily all, layers of a Python application.

With return type hints, type checkers, such as Mypy, can identify when unexceptional
exceptions are not being handled properly.

See the README.md in https://gitlab.com/castedo/unexceptional for more information.
"""

from __future__ import annotations

from types import TracebackType
from typing import TYPE_CHECKING, TypeVar, cast

if TYPE_CHECKING:
    ExceptionT = TypeVar('ExceptionT', bound='Exception')
    NonExceptionT = TypeVar('NonExceptionT')


def cast_or_raise(ret: NonExceptionT | Exception) -> NonExceptionT:
    """Cast a value to a non-Exception type or raise an Exception.

    Example:
        def do_fancy_math(x: float) -> float | ValueError:
            ...

        try:
            ...
            y = cast_or_raise(do_fancy_math(x))
            # mypy knows y is a float here
            ...
        except ValueEror:
            ...
    """
    if isinstance(ret, Exception):
        raise ret
    return ret


def unexceptional(ex: ExceptionT, cause: Exception | None = None) -> ExceptionT:
    """Return an Exception object with a stack trace and optional cause.

    Example:
        if bad_case:
            return unexceptional(ValueError("Bad case"))
    """
    try:
        raise ex
    except Exception as ret:
        ret.__cause__ = cause
        if not ret.__traceback__:
            return cast('ExceptionT', ret)
        frame = ret.__traceback__.tb_frame
        frame = frame.f_back or frame
        tb = TracebackType(None, frame, frame.f_lasti, frame.f_lineno)
        return cast('ExceptionT', ret.with_traceback(tb))
