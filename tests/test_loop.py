# SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
# Copyright 2025 Fantix King

import asyncio
import contextvars
import gc
import sys
import unittest

import compio


def has_io_uring_support() -> bool:
    """Check if the system has io_uring support enabled.

    This checks if io_uring is disabled via the kernel.io_uring_disabled sysctl.
    If the sysctl doesn't exist, falls back to checking /proc/kallsyms for io_uring symbols.
    Returns True if io_uring is available (not disabled), False otherwise.
    """
    if not sys.platform.startswith("linux"):
        return False

    try:
        # Check if kernel.io_uring_disabled is set to 0 (enabled)
        with open("/proc/sys/kernel/io_uring_disabled") as f:
            value = f.read().strip()
            return value == "0"
    except FileNotFoundError:
        # If the sysctl doesn't exist, check /proc/kallsyms as fallback
        # to see if io_uring symbols are present in the kernel
        try:
            with open("/proc/kallsyms") as f:
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
    def test_create_loop(self) -> None:
        """Test that a CompioLoop can be created."""
        loop = compio.CompioLoop()
        self.assertIsInstance(loop, asyncio.AbstractEventLoop)

    def test_driver_type(self) -> None:
        """Test that driver_type property returns a valid DriverType."""
        loop = compio.CompioLoop()
        self.assertIsInstance(loop.get_driver_type(), compio.DriverType)

        # Platform-specific driver type validation
        if sys.platform == "win32":
            # Windows should use IOCP
            self.assertEqual(loop.get_driver_type(), compio.DriverType.IOCP)
        elif has_io_uring_support():
            # Linux with successful io_uring driver initialization
            self.assertEqual(loop.get_driver_type(), compio.DriverType.IO_URING)
        else:
            # Otherwise, should fall back to POLL
            self.assertEqual(loop.get_driver_type(), compio.DriverType.POLL)

    def test_driver_type_in_repr(self) -> None:
        """Test that driver_type appears in the repr string."""
        loop = compio.CompioLoop()
        repr_str = repr(loop)
        self.assertIn("CompioLoop", repr_str)
        self.assertIn(loop.get_driver_type().value, repr_str)

    def test_no_memory_leak(self) -> None:
        """Test that creating and destroying loops doesn't leak Python objects."""

        # Force garbage collection to start with a clean slate
        gc.collect()

        # Get initial object count
        initial_objects = len(gc.get_objects())

        # Create and destroy loops multiple times
        for _ in range(100):
            loop = compio.CompioLoop()
            # Access some properties to ensure full initialization
            _ = loop.get_driver_type()
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


class TestLoopState(unittest.TestCase):
    def test_initial_state(self) -> None:
        """Test initial state of a new loop."""
        loop = compio.CompioLoop()
        self.assertFalse(loop.is_running())
        self.assertFalse(loop.is_closed())

    def test_closed_state_after_close(self) -> None:
        """Test that is_closed returns True after close."""
        loop = compio.CompioLoop()
        loop.close()
        self.assertTrue(loop.is_closed())
        self.assertFalse(loop.is_running())

    def test_close_idempotent(self) -> None:
        """Test that close can be called multiple times."""
        loop = compio.CompioLoop()
        loop.close()
        loop.close()  # Should not raise
        self.assertTrue(loop.is_closed())

    def test_operations_on_closed_loop_raise(self) -> None:
        """Test that operations on closed loop raise RuntimeError."""
        loop = compio.CompioLoop()
        loop.close()

        with self.assertRaises(RuntimeError):
            loop.get_driver_type()

        with self.assertRaises(RuntimeError):
            loop.call_soon(lambda: None)


class TestCallSoon(unittest.TestCase):
    def test_call_soon_returns_handle(self) -> None:
        """Test that call_soon returns a Handle."""
        loop = compio.CompioLoop()
        handle = loop.call_soon(lambda: None)
        self.assertIsInstance(handle, compio.Handle)
        loop.close()

    def test_call_soon_with_args(self) -> None:
        """Test call_soon with arguments."""
        loop = compio.CompioLoop()
        results: list[tuple[int, int, int]] = []

        def callback(a: int, b: int, c: int) -> None:
            results.append((a, b, c))

        loop.call_soon(callback, 1, 2, 3)
        loop.call_soon(loop.stop)
        loop.run_forever()

        self.assertEqual(results, [(1, 2, 3)])
        loop.close()

    def test_call_soon_execution_order(self) -> None:
        """Test that callbacks are executed in FIFO order."""
        loop = compio.CompioLoop()
        results: list[int] = []

        for i in range(5):
            loop.call_soon(results.append, i)
        loop.call_soon(loop.stop)
        loop.run_forever()

        self.assertEqual(results, [0, 1, 2, 3, 4])
        loop.close()


class TestHandle(unittest.TestCase):
    def test_handle_cancel(self) -> None:
        """Test that cancelled handle's callback is not executed."""
        loop = compio.CompioLoop()
        results: list[str] = []

        handle = loop.call_soon(results.append, "cancelled")
        loop.call_soon(results.append, "executed")
        handle.cancel()
        loop.call_soon(loop.stop)
        loop.run_forever()

        self.assertEqual(results, ["executed"])
        loop.close()

    def test_handle_cancelled_state(self) -> None:
        """Test handle.cancelled() returns correct state."""
        loop = compio.CompioLoop()
        handle = loop.call_soon(lambda: None)

        self.assertFalse(handle.cancelled())
        handle.cancel()
        self.assertTrue(handle.cancelled())
        loop.close()

    def test_handle_cancel_idempotent(self) -> None:
        """Test that cancel can be called multiple times."""
        loop = compio.CompioLoop()
        handle = loop.call_soon(lambda: None)

        handle.cancel()
        handle.cancel()  # Should not raise
        self.assertTrue(handle.cancelled())
        loop.close()


class TestRunForever(unittest.TestCase):
    def test_run_forever_and_stop(self) -> None:
        """Test run_forever stops when stop is called."""
        loop = compio.CompioLoop()
        results: list[int] = []

        loop.call_soon(results.append, 1)
        loop.call_soon(results.append, 2)
        loop.call_soon(loop.stop)
        loop.call_soon(results.append, 3)

        loop.run_forever()

        # All callbacks scheduled before run_forever are executed in the same iteration,
        # stop() sets the flag which is checked after processing the ready queue
        self.assertEqual(results, [1, 2, 3])
        loop.close()

    def test_is_running_during_run(self) -> None:
        """Test that is_running returns True during run_forever."""
        loop = compio.CompioLoop()
        running_state: list[bool] = []

        def check_running() -> None:
            running_state.append(loop.is_running())
            loop.stop()

        loop.call_soon(check_running)
        loop.run_forever()

        self.assertEqual(running_state, [True])
        self.assertFalse(loop.is_running())
        loop.close()

    def test_run_forever_already_running(self) -> None:
        """Test that running loop twice raises RuntimeError."""
        loop = compio.CompioLoop()
        error_raised: list[str] = []

        def try_run_again() -> None:
            try:
                loop.run_forever()
            except RuntimeError as e:
                error_raised.append(str(e))
            loop.stop()

        loop.call_soon(try_run_again)
        loop.run_forever()

        self.assertEqual(len(error_raised), 1)
        self.assertIn("already running", error_raised[0])
        loop.close()

    def test_stop_before_run(self) -> None:
        """Test that stop before run_forever causes immediate return."""
        loop = compio.CompioLoop()
        results: list[int] = []

        loop.call_soon(results.append, 1)
        loop.stop()
        loop.run_forever()

        # Callbacks should still be processed until stop is checked
        self.assertEqual(results, [1])
        loop.close()

    def test_run_forever_can_restart(self) -> None:
        """Test that run_forever can be called again after stopping."""
        loop = compio.CompioLoop()
        results: list[str] = []

        loop.call_soon(results.append, "first")
        loop.call_soon(loop.stop)
        loop.run_forever()

        loop.call_soon(results.append, "second")
        loop.call_soon(loop.stop)
        loop.run_forever()

        self.assertEqual(results, ["first", "second"])
        loop.close()


class TestContextVars(unittest.TestCase):
    def test_call_soon_copies_context(self) -> None:
        """Test that call_soon copies current context."""
        loop = compio.CompioLoop()
        var: contextvars.ContextVar[str] = contextvars.ContextVar("test_var")
        results: list[str] = []

        var.set("original")

        def callback() -> None:
            results.append(var.get())

        loop.call_soon(callback)

        # Change value after scheduling
        var.set("changed")

        loop.call_soon(loop.stop)
        loop.run_forever()

        # Callback should see "original" since context was copied at schedule time
        self.assertEqual(results, ["original"])
        loop.close()

    def test_call_soon_with_explicit_context(self) -> None:
        """Test call_soon with explicit context argument."""
        loop = compio.CompioLoop()
        var: contextvars.ContextVar[str] = contextvars.ContextVar("test_var")
        results: list[str] = []

        def callback() -> None:
            results.append(var.get())

        # Create a context with a specific value
        var.set("in_context")
        ctx = contextvars.copy_context()

        # Schedule with explicit context
        loop.call_soon(callback, context=ctx)
        loop.call_soon(loop.stop)
        loop.run_forever()

        self.assertEqual(results, ["in_context"])
        loop.close()


class TestClose(unittest.TestCase):
    def test_cannot_close_running_loop(self) -> None:
        """Test that closing a running loop raises RuntimeError."""
        loop = compio.CompioLoop()
        error_raised: list[str] = []

        def try_close() -> None:
            try:
                loop.close()
            except RuntimeError as e:
                error_raised.append(str(e))
            loop.stop()

        loop.call_soon(try_close)
        loop.run_forever()

        self.assertEqual(len(error_raised), 1)
        self.assertIn("running", error_raised[0].lower())
        loop.close()


class TestRepr(unittest.TestCase):
    def test_repr_shows_running_state(self) -> None:
        """Test that repr shows running state correctly."""
        loop = compio.CompioLoop()

        repr_before = repr(loop)
        self.assertIn("running=False", repr_before)

        running_repr: list[str] = []

        def capture_repr() -> None:
            running_repr.append(repr(loop))
            loop.stop()

        loop.call_soon(capture_repr)
        loop.run_forever()

        self.assertIn("running=True", running_repr[0])
        loop.close()

    def test_repr_shows_closed_state(self) -> None:
        """Test that repr shows closed state correctly."""
        loop = compio.CompioLoop()

        repr_before = repr(loop)
        self.assertIn("closed=False", repr_before)

        loop.close()
        repr_after = repr(loop)
        self.assertIn("closed=True", repr_after)
