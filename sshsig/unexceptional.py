# (c) 2024 E. Castedo Ellerman <castedo@castedo.com>
# Released under the MIT License (https://spdx.org/licenses/MIT)

# https://lukeplant.me.uk/blog/posts/raising-exceptions-or-returning-error-objects-in-python/

# "Do. Or do not. There is no try."
#                           -- Yoda


from __future__ import annotations

from types import TracebackType
from typing import TYPE_CHECKING, TypeVar, cast


if TYPE_CHECKING:
    ExceptionT = TypeVar('ExceptionT', bound='Exception')
    NonExceptionT = TypeVar('NonExceptionT')


def cast_or_raise(ret: NonExceptionT | Exception) -> NonExceptionT:
    if isinstance(ret, Exception):
        raise ret
    return ret


def unexceptional(ex: ExceptionT, cause: Exception | None = None) -> ExceptionT:
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


# MORE ACKS:
# https://stackoverflow.com/a/58821552/2420027
