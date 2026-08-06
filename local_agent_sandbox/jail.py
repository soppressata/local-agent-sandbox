"""
Rootless filesystem jail for sandboxed child processes.

Parent installs uid/gid maps (via newuidmap/newgidmap when multi-uid
maps are required); the child builds a minimal chroot, drops to
nobody:nogroup (65534), and execs the command.
"""

import ctypes
import ctypes.util
import os
import pwd
import select
import signal
import stat
import subprocess
import time
from typing import Dict, List, Optional, Tuple


MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 262144

NOBODY_UID = 65534
NOBODY_GID = 65534

_RO_HOST_PATHS = ("/bin", "/usr", "/lib", "/lib64")
_DEV_NODES = (
    ("null", 1, 3, 0o666),
    ("zero", 1, 5, 0o666),
    ("full", 1, 7, 0o666),
    ("random", 1, 8, 0o666),
    ("urandom", 1, 9, 0o666),
    ("tty", 5, 0, 0o666),
)


class JailSetupError(RuntimeError):
    """Raised when filesystem isolation cannot be established."""


def _libc():
    libname = ctypes.util.find_library("c")
    if not libname:
        raise JailSetupError("Unable to locate libc for mount(2)")
    lib = ctypes.CDLL(libname, use_errno=True)
    lib.mount.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
    ]
    lib.mount.restype = ctypes.c_int
    return lib


def _mount(
    source: Optional[str],
    target: str,
    fstype: Optional[str] = None,
    flags: int = 0,
    data: Optional[str] = None,
) -> None:
    lib = _libc()
    src = source.encode() if source is not None else None
    tgt = target.encode()
    fs = fstype.encode() if fstype is not None else None
    dt = data.encode() if data is not None else None
    if lib.mount(src, tgt, fs, ctypes.c_ulong(flags), dt) != 0:
        err = ctypes.get_errno()
        raise JailSetupError(
            f"mount({source!r}, {target!r}, fstype={fstype!r}, flags=0x{flags:x}) "
            f"failed: {os.strerror(err)} (errno={err})"
        )


def _bind_ro(src: str, dst: str) -> None:
    os.makedirs(dst, exist_ok=True)
    _mount(src, dst, None, MS_BIND | MS_REC)
    _mount(src, dst, None, MS_BIND | MS_REC | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)


def _setup_dev(jail_root: str) -> None:
    dev = os.path.join(jail_root, "dev")
    os.makedirs(dev, exist_ok=True)
    _mount("tmpfs", dev, "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755,size=1m")
    for name, _major, _minor, _mode in _DEV_NODES:
        src = f"/dev/{name}"
        dst = os.path.join(dev, name)
        if not os.path.exists(src):
            continue
        # Device nodes cannot be mknod()'d inside an unprivileged user
        # namespace; bind-mount the host nodes instead.
        try:
            with open(dst, "wb"):
                pass
            _mount(src, dst, None, MS_BIND)
        except OSError as e:
            raise JailSetupError(f"Failed to bind-mount {src}: {e}") from e


def _unshare_flags() -> int:
    flags = 0
    for name, default_val in (
        ("CLONE_NEWUSER", 0x10000000),
        ("CLONE_NEWNS", 0x00020000),
        ("CLONE_NEWUTS", 0x04000000),
        ("CLONE_NEWIPC", 0x08000000),
    ):
        flags |= getattr(os, name, default_val)
    return flags


def _read_subid_start(path: str, username: str) -> int:
    try:
        with open(path, "r", encoding="ascii") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) >= 3 and parts[0] == username:
                    return int(parts[1])
    except OSError as e:
        raise JailSetupError(f"Cannot read {path}: {e}") from e
    raise JailSetupError(
        f"No subordinate id entry for user {username!r} in {path}. "
        "Add a range (e.g. via usermod --add-subuids) or install/configure uidmap."
    )


def _find_helper(name: str) -> str:
    for candidate in (f"/usr/bin/{name}", f"/bin/{name}", name):
        if candidate == name:
            from shutil import which
            found = which(name)
            if found:
                return found
            continue
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise JailSetupError(
        f"{name} not found. Install the 'uidmap' package to enable "
        "real filesystem isolation (uid/gid mapping + nobody drop)."
    )


def _write_child_id_maps(pid: int, real_uid: int, real_gid: int) -> None:
    try:
        with open(f"/proc/{pid}/setgroups", "w", encoding="ascii") as f:
            f.write("deny")
    except OSError as e:
        raise JailSetupError(f"Failed to write setgroups for pid {pid}: {e}") from e

    username = pwd.getpwuid(real_uid).pw_name
    subuid = _read_subid_start("/etc/subuid", username)
    subgid = _read_subid_start("/etc/subgid", username)
    newuidmap = _find_helper("newuidmap")
    newgidmap = _find_helper("newgidmap")

    uid_cmd = [
        newuidmap, str(pid),
        "0", str(real_uid), "1",
        str(NOBODY_UID), str(subuid), "1",
    ]
    gid_cmd = [
        newgidmap, str(pid),
        "0", str(real_gid), "1",
        str(NOBODY_GID), str(subgid), "1",
    ]

    for cmd in (uid_cmd, gid_cmd):
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except OSError as e:
            raise JailSetupError(f"Failed to execute {cmd[0]}: {e}") from e
        if res.returncode != 0:
            err = (res.stderr or res.stdout or "").strip()
            raise JailSetupError(
                f"{cmd[0]} failed (exit {res.returncode}): {err or 'unknown error'}"
            )


def _child_build_jail_and_exec(
    work_dir: str,
    command: str,
    env: Dict[str, str],
    stdout_fd: int,
    stderr_fd: int,
    pre_exec=None,
) -> None:
    if pre_exec is not None:
        pre_exec()

    _mount(None, "/", None, MS_REC | MS_PRIVATE)

    jail_root = os.path.join(work_dir, ".las_jail")
    try:
        os.makedirs(jail_root, mode=0o755, exist_ok=True)
    except OSError as e:
        raise JailSetupError(f"Failed to create jail root {jail_root}: {e}") from e

    host_paths = [p for p in _RO_HOST_PATHS if os.path.exists(p)]
    if "/bin" not in host_paths and "/usr" not in host_paths:
        raise JailSetupError("Neither /bin nor /usr exists on host; cannot build jail")

    for src in host_paths:
        dst = os.path.join(jail_root, src.lstrip("/"))
        _bind_ro(src, dst)

    _setup_dev(jail_root)

    workspace = os.path.join(jail_root, "workspace")
    try:
        os.makedirs(workspace, mode=0o777, exist_ok=True)
        os.chmod(work_dir, 0o777)
        os.chmod(workspace, 0o777)
    except OSError as e:
        raise JailSetupError(f"Failed to prepare workspace mount: {e}") from e

    _mount(work_dir, workspace, None, MS_BIND)

    try:
        os.chroot(jail_root)
        os.chdir("/workspace")
    except OSError as e:
        raise JailSetupError(f"chroot/chdir failed: {e}") from e

    try:
        os.setgroups([])
    except OSError as e:
        if getattr(e, "errno", None) != 1:
            raise JailSetupError(f"setgroups([]) failed: {e}") from e

    try:
        os.setgid(NOBODY_GID)
        os.setuid(NOBODY_UID)
    except OSError as e:
        raise JailSetupError(f"Failed to drop privileges to nobody:nogroup: {e}") from e

    if os.getuid() != NOBODY_UID or os.getgid() != NOBODY_GID:
        raise JailSetupError(
            f"Privilege drop incomplete: uid={os.getuid()} gid={os.getgid()}"
        )

    os.dup2(stdout_fd, 1)
    os.dup2(stderr_fd, 2)
    if stdout_fd not in (0, 1, 2):
        os.close(stdout_fd)
    if stderr_fd not in (0, 1, 2, stdout_fd):
        os.close(stderr_fd)

    os.environ.clear()
    os.environ.update(env)
    os.execve("/bin/bash", ["bash", "-c", command], env)


def _read_fd(fd: int) -> bytes:
    chunks: List[bytes] = []
    while True:
        try:
            data = os.read(fd, 65536)
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)


def run_jailed(
    command: str,
    work_dir: str,
    env: Dict[str, str],
    timeout_seconds: float,
    pre_exec=None,
) -> Tuple[int, str, str]:
    """
    Run command inside a real rootless filesystem jail.

    Returns (exit_code, stdout, stderr). Raises JailSetupError if isolation
    cannot be established (never falls back to an unisolated run).
    """
    if not work_dir or not os.path.isdir(work_dir):
        raise JailSetupError(f"work_dir is not a directory: {work_dir!r}")

    real_uid = os.getuid()
    real_gid = os.getgid()

    sync_r, sync_w = os.pipe()
    map_r, map_w = os.pipe()
    err_r, err_w = os.pipe()
    out_r, out_w = os.pipe()
    err_out_r, err_out_w = os.pipe()

    pid = os.fork()
    if pid == 0:
        try:
            os.close(sync_r)
            os.close(map_w)
            os.close(err_r)
            os.close(out_r)
            os.close(err_out_r)

            try:
                os.unshare(_unshare_flags())
            except OSError as e:
                msg = (
                    f"unshare failed: {e}. "
                    "Unprivileged user namespaces may be disabled on this host."
                ).encode()
                os.write(err_w, msg)
                os._exit(126)

            os.write(sync_w, b"1")
            os.close(sync_w)

            ready = os.read(map_r, 1)
            os.close(map_r)
            if ready != b"1":
                os.write(err_w, b"Parent failed to install uid/gid maps")
                os._exit(126)

            try:
                _child_build_jail_and_exec(
                    work_dir, command, env, out_w, err_out_w, pre_exec=pre_exec
                )
            except BaseException as e:
                try:
                    os.write(err_w, f"Jail setup failed: {e}".encode())
                except Exception:
                    pass
                os._exit(126)
            os._exit(126)
        except BaseException as e:
            try:
                os.write(err_w, f"Jail setup failed: {e}".encode())
            except Exception:
                pass
            os._exit(126)

    os.close(sync_w)
    os.close(map_r)
    os.close(err_w)
    os.close(out_w)
    os.close(err_out_w)

    try:
        ready = os.read(sync_r, 1)
        os.close(sync_r)
        if ready != b"1":
            setup_err = _read_fd(err_r).decode(errors="replace")
            os.close(err_r)
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            os.waitpid(pid, 0)
            raise JailSetupError(setup_err or "Child failed before unshare completed")

        try:
            _write_child_id_maps(pid, real_uid, real_gid)
        except JailSetupError:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            os.waitpid(pid, 0)
            os.close(map_w)
            os.close(err_r)
            os.close(out_r)
            os.close(err_out_r)
            raise

        os.write(map_w, b"1")
        os.close(map_w)

        deadline = time.monotonic() + timeout_seconds
        stdout_buf = bytearray()
        stderr_buf = bytearray()
        open_fds = {out_r, err_out_r, err_r}

        timed_out = False
        while open_fds:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            readable, _, _ = select.select(list(open_fds), [], [], min(remaining, 0.2))
            if not readable:
                try:
                    waited_pid, _ = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    waited_pid = pid
                if waited_pid == pid:
                    for fd in list(open_fds):
                        data = _read_fd(fd)
                        if fd == out_r:
                            stdout_buf.extend(data)
                        else:
                            stderr_buf.extend(data)
                        os.close(fd)
                        open_fds.discard(fd)
                    break
                continue
            for fd in readable:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    data = b""
                if not data:
                    os.close(fd)
                    open_fds.discard(fd)
                    continue
                if fd == out_r:
                    stdout_buf.extend(data)
                else:
                    stderr_buf.extend(data)

        if timed_out:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            for fd in list(open_fds):
                try:
                    os.close(fd)
                except OSError:
                    pass
            return 124, stdout_buf.decode(errors="replace"), (
                f"Command execution timed out after {timeout_seconds} seconds."
            )

        try:
            _, status = os.waitpid(pid, 0)
        except ChildProcessError:
            status = 0

        for fd in list(open_fds):
            data = _read_fd(fd)
            if fd == out_r:
                stdout_buf.extend(data)
            else:
                stderr_buf.extend(data)
            try:
                os.close(fd)
            except OSError:
                pass

        if os.WIFEXITED(status):
            code = os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            code = 128 + os.WTERMSIG(status)
        else:
            code = 1

        stdout = stdout_buf.decode(errors="replace")
        stderr = stderr_buf.decode(errors="replace")

        if code == 126 and stderr and (
            "Jail setup failed" in stderr or "unshare failed" in stderr
        ):
            raise JailSetupError(stderr.strip())

        return code, stdout, stderr
    except Exception:
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        except OSError:
            pass
        raise
