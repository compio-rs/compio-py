# SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
# Copyright 2025 Fantix King

import asyncio
import enum

from compio import _core


class DriverType(enum.StrEnum):
    IO_URING = "IoUring"
    POLL = "Poll"
    IOCP = "IOCP"


class CompioLoop(_core.CompioLoop, asyncio.AbstractEventLoop):
    def get_driver_type(self) -> DriverType:
        return DriverType(super().get_driver_type())

    def __repr__(self):
        try:
            driver_type = f"driver={self.get_driver_type().value} "
        except RuntimeError:
            driver_type = ""
        return (
            f"<{self.__class__.__name__} "
            f"{driver_type}"
            f"running={self.is_running()} "
            f"closed={self.is_closed()}>"
        )
