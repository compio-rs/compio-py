import asyncio
import gc
import os
import sys
import unittest

import compio


def has_io_uring_support():
    """Check if the system has io_uring support enabled.

    This checks if io_uring is disabled via the kernel.io_uring_disabled sysctl.
    If the sysctl doesn't exist, falls back to checking /proc/kallsyms for io_uring symbols.
    Returns True if io_uring is available (not disabled), False otherwise.
    """
    if not sys.platform.startswith("linux"):
        return False

    try:
        # Check if kernel.io_uring_disabled is set to 0 (enabled)
        with open("/proc/sys/kernel/io_uring_disabled", "r") as f:
            value = f.read().strip()
            return value == "0"
    except FileNotFoundError:
        # If the sysctl doesn't exist, check /proc/kallsyms as fallback
        # to see if io_uring symbols are present in the kernel
        try:
            with open("/proc/kallsyms", "r") as f:
                for line in f:
                    # Look for io_uring_setup symbol which is the main entry point
                    if "io_uring_setup" in line:
                        return True
            return False
        except (FileNotFoundError, PermissionError):
            # If we can't read kallsyms, assume io_uring is not available
            return False
    except PermissionError:
        # If we can't read the sysctl due to permissions, assume unavailable
        return False


class TestCompioLoop(unittest.TestCase):
    def test_create_loop(self):
        """Test that a CompioLoop can be created."""
        loop = compio.CompioLoop()
        self.assertIsInstance(loop, asyncio.AbstractEventLoop)

    def test_driver_type(self):
        """Test that driver_type property returns a valid DriverType."""
        loop = compio.CompioLoop()
        self.assertIsInstance(loop.driver_type, compio.DriverType)

        # Platform-specific driver type validation
        if sys.platform == "win32":
            # Windows should use IOCP
            self.assertEqual(loop.driver_type, compio.DriverType.IOCP)
        elif has_io_uring_support():
            # Linux with successful io_uring driver initialization
            self.assertEqual(loop.driver_type, compio.DriverType.IO_URING)
        else:
            # Otherwise, should fall back to POLL
            self.assertEqual(loop.driver_type, compio.DriverType.POLL)

    def test_driver_type_in_repr(self):
        """Test that driver_type appears in the repr string."""
        loop = compio.CompioLoop()
        repr_str = repr(loop)
        self.assertIn("CompioLoop", repr_str)
        self.assertIn(loop.driver_type.value, repr_str)

    def test_no_memory_leak(self):
        """Test that creating and destroying loops doesn't leak Python objects."""

        # Force garbage collection to start with a clean slate
        gc.collect()

        # Get initial object count
        initial_objects = len(gc.get_objects())

        # Create and destroy loops multiple times
        for _ in range(100):
            loop = compio.CompioLoop()
            # Access some properties to ensure full initialization
            _ = loop.driver_type
            _ = repr(loop)
            # Explicitly delete the loop
            del loop

        # Force garbage collection
        gc.collect()

        # Get final object count
        final_objects = len(gc.get_objects())

        # Allow some tolerance for GC internals and Python runtime overhead
        # but the difference should be small (< 50 objects for 100 iterations)
        object_diff = final_objects - initial_objects
        self.assertLess(
            object_diff,
            50,
            f"Possible memory leak: {object_diff} objects leaked after 100 loop creations"
        )
