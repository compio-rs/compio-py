import asyncio
import enum

from compio import _core

class DriverType(enum.StrEnum):
    IO_URING = "IoUring"
    POLL = "Poll"
    IOCP = "IOCP"


class CompioLoop(asyncio.AbstractEventLoop):
    __slots__ = ("__runtime", "_driver_type")

    def __init__(self):
        self.__runtime = _core.make_runtime(self)
        self._driver_type = DriverType(self.__runtime.driver_type())

    def __repr__(self):
        return f"<CompioLoop driver={self._driver_type}>"

    @property
    def driver_type(self) -> DriverType:
        return self._driver_type
