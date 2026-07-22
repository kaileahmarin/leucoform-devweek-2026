"""Bounded-memory subprocess output handling for hostile child processes."""

from __future__ import annotations

import codecs
import os
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, TextIO

from .util import sanitize_terminal

ProcessRunner = Callable[..., subprocess.CompletedProcess[bytes]]
PopenFactory = Callable[..., subprocess.Popen[bytes]]
MAX_STDIN_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class CancellableProcessResult:
    returncode: int
    cancelled: bool


class WindowsBatchCommandError(OSError):
    """Raised when Windows would implicitly reinterpret argv through cmd.exe."""


def _windows_batch_target(command: Sequence[str], env: Mapping[str, str]) -> str | None:
    if os.name != "nt" or not command:
        return None
    executable = command[0]
    if Path(executable).suffix.casefold() in {".bat", ".cmd"}:
        return executable
    path = next((value for key, value in env.items() if key.casefold() == "path"), None)
    resolved = shutil.which(executable, path=path)
    if resolved is not None and Path(resolved).suffix.casefold() in {".bat", ".cmd"}:
        return resolved
    return None


def _emit_sanitized(destination: TextIO, value: str) -> bool:
    """Write sanitized text, returning false if the destination became unusable."""

    if not value:
        return True
    try:
        destination.write(sanitize_terminal(value))
        destination.flush()
    except (OSError, UnicodeError, ValueError):
        # A closed pipe or an incompatible terminal encoding must not stop pipe
        # draining: doing so could deadlock a child that continues writing.
        return False
    return True


def _drain_pipe(source: BinaryIO, destination: TextIO) -> None:
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    writable = True
    try:
        while chunk := source.read(64 * 1024):
            text = decoder.decode(chunk, final=False)
            if writable:
                writable = _emit_sanitized(destination, text)
        tail = decoder.decode(b"", final=True)
        if writable:
            _emit_sanitized(destination, tail)
    finally:
        source.close()


def _drain_pipe_callback(
    source: BinaryIO,
    callback: Callable[[str], None],
    *,
    sanitize: bool,
) -> None:
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    usable = True
    try:
        while chunk := source.read(64 * 1024):
            text = decoder.decode(chunk, final=False)
            if sanitize:
                text = sanitize_terminal(text)
            if usable and text:
                try:
                    callback(text)
                except Exception:
                    usable = False
        tail = decoder.decode(b"", final=True)
        if sanitize:
            tail = sanitize_terminal(tail)
        if usable and tail:
            with suppress(Exception):
                callback(tail)
    finally:
        source.close()


def _write_stdin(destination: BinaryIO, value: bytes) -> None:
    try:
        destination.write(value)
        destination.flush()
    except (BrokenPipeError, OSError, ValueError):
        pass
    finally:
        destination.close()


def run_sanitized_process(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    runner: ProcessRunner,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run argv without a shell and stream sanitized stdout/stderr concurrently.

    Output is decoded incrementally as UTF-8 with replacement and is never retained
    or persisted. Independent drain threads keep both bounded OS pipes flowing even
    when a child writes heavily to stdout and stderr at the same time.
    """

    batch_target = _windows_batch_target(command, env)
    if batch_target is not None:
        raise WindowsBatchCommandError(
            "Direct Windows batch execution is refused; invoke cmd.exe explicitly "
            "if shell parsing is intended"
        )

    stdout_read_fd, stdout_write_fd = os.pipe()
    stderr_read_fd, stderr_write_fd = os.pipe()
    stdout_read = os.fdopen(stdout_read_fd, "rb", buffering=0)
    stderr_read = os.fdopen(stderr_read_fd, "rb", buffering=0)
    stdout_write = os.fdopen(stdout_write_fd, "wb", buffering=0)
    stderr_write = os.fdopen(stderr_write_fd, "wb", buffering=0)
    stdout_thread = threading.Thread(
        target=_drain_pipe,
        args=(stdout_read, stdout if stdout is not None else sys.stdout),
        name="notug-child-stdout",
    )
    stderr_thread = threading.Thread(
        target=_drain_pipe,
        args=(stderr_read, stderr if stderr is not None else sys.stderr),
        name="notug-child-stderr",
    )
    stdout_thread.start()
    stderr_thread.start()
    try:
        completed = runner(
            list(command),
            cwd=cwd,
            env=dict(env),
            stdout=stdout_write,
            stderr=stderr_write,
            check=False,
            shell=False,
        )
    finally:
        stdout_write.close()
        stderr_write.close()
        stdout_thread.join()
        stderr_thread.join()
    return int(completed.returncode)


def run_cancellable_process(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    input_bytes: bytes,
    stdout_callback: Callable[[str], None],
    stderr_callback: Callable[[str], None],
    cancel_event: threading.Event,
    popen_factory: PopenFactory = subprocess.Popen,
    hide_window: bool = False,
) -> CancellableProcessResult:
    """Run a bounded-input child without retaining output.

    Structured stdout preserves its original JSONL line framing for the caller's
    parser. Unstructured stderr remains terminal-sanitized on its independent
    pipe. Parsed stdout must be sanitized before human display.
    """

    if len(input_bytes) > MAX_STDIN_BYTES:
        raise ValueError("Process stdin exceeds the one-megabyte safety bound")
    batch_target = _windows_batch_target(command, env)
    if batch_target is not None:
        raise WindowsBatchCommandError(
            "Direct Windows batch execution is refused; invoke cmd.exe explicitly "
            "if shell parsing is intended"
        )
    creationflags = 0
    if hide_window and os.name == "nt":
        creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
    process = popen_factory(
        list(command),
        cwd=cwd,
        env=dict(env),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        creationflags=creationflags,
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        process.kill()
        raise OSError("Child process pipes were not created")
    stdout_thread = threading.Thread(
        target=_drain_pipe_callback,
        args=(process.stdout, stdout_callback),
        kwargs={"sanitize": False},
        name="notug-stream-stdout",
    )
    stderr_thread = threading.Thread(
        target=_drain_pipe_callback,
        args=(process.stderr, stderr_callback),
        kwargs={"sanitize": True},
        name="notug-stream-stderr",
    )
    stdin_thread = threading.Thread(
        target=_write_stdin,
        args=(process.stdin, input_bytes),
        name="notug-stream-stdin",
    )
    stdout_thread.start()
    stderr_thread.start()
    stdin_thread.start()
    cancelled = False
    try:
        while process.poll() is None:
            if cancel_event.wait(0.05):
                cancelled = True
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                break
        returncode = int(process.wait())
    finally:
        stdin_thread.join()
        stdout_thread.join()
        stderr_thread.join()
    return CancellableProcessResult(returncode=returncode, cancelled=cancelled)
