"""Deadline-bound pipe I/O and owned process-group cleanup for POSIX calls."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from io import TextIOWrapper
from pathlib import Path
from typing import Any, cast


def decode_output(data: bytes, encoding: str) -> str:
    """Match text-mode subprocess output without exposing undecodable payloads."""
    try:
        return data.decode(encoding).replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeDecodeError:
        # ValueError subclasses would be classified as invalid client arguments.
        raise RuntimeError("skill output could not be decoded as text") from None


def overflow_result(command: list[str], max_bytes: int) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        command,
        1,
        "",
        "skill output exceeded CLOUD_SECURITY_MCP_WORKER_MAX_BYTES "
        f"({max_bytes} bytes); process killed",
    )


def run_posix(
    command: list[str],
    *,
    stdin_text: str,
    cwd: str | Path,
    env: dict[str, str] | None,
    timeout: float,
    preexec_fn: Any,
    max_bytes: int,
) -> subprocess.CompletedProcess[str]:
    """Bound I/O and process wait by one deadline after subprocess creation.

    The session belongs to this invocation. Ordinary descendants are cleaned up
    even if the direct child has exited; deliberately detached processes are not
    contained by a process group. No pipe reader or writer threads are created.
    """
    with subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=cwd,
        env=env,
        preexec_fn=preexec_fn,
        start_new_session=True,
    ) as proc:
        deadline = time.monotonic() + timeout
        assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
        encoding = cast(TextIOWrapper, proc.stdout).encoding
        captured = {"stdout": bytearray(), "stderr": bytearray()}
        try:
            pending = memoryview(stdin_text.encode(encoding))
            with selectors.DefaultSelector() as selector:
                for name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                if pending:
                    os.set_blocking(proc.stdin.fileno(), False)
                    selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
                else:
                    proc.stdin.close()
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    for key, _ in selector.select(remaining):
                        ready_stream = key.fileobj
                        if key.data == "stdin":
                            try:
                                # Small nonblocking writes keep stdout/stderr responsive.
                                pending = pending[os.write(key.fd, pending[:4096]) :]
                            except BlockingIOError:
                                continue
                            except BrokenPipeError:
                                pending = pending[:0]
                            if not pending:
                                selector.unregister(ready_stream)
                                proc.stdin.close()
                        else:
                            output = captured[key.data]
                            try:
                                chunk = os.read(key.fd, min(65536, max_bytes - len(output) + 1))
                            except BlockingIOError:
                                continue
                            if not chunk:
                                selector.unregister(ready_stream)
                            elif len(output) + len(chunk) > max_bytes:
                                return overflow_result(command, max_bytes)
                            else:
                                output.extend(chunk)
                remaining = deadline - time.monotonic()
                if remaining <= 0 and proc.poll() is None:
                    raise subprocess.TimeoutExpired(command, timeout)
                try:
                    returncode = proc.wait(timeout=max(0, remaining))
                except subprocess.TimeoutExpired:
                    raise subprocess.TimeoutExpired(command, timeout) from None
            return subprocess.CompletedProcess(
                command,
                returncode,
                decode_output(bytes(captured["stdout"]), encoding),
                decode_output(bytes(captured["stderr"]), encoding),
            )
        finally:
            # Always target only the new session's group, including after leader exit.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
