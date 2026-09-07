"""Bounded descriptor-based reads of caller-provided regular files."""
import os
import stat


def read_regular(path, limit, *, uid=None, modes=None, reject_writable=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("input must be a regular non-symlink file")
        if uid is not None and metadata.st_uid != uid:
            raise ValueError("input ownership is unsafe")
        if (modes is not None and mode not in modes) or (reject_writable and mode & 0o022):
            raise ValueError("input permissions are unsafe")
        if metadata.st_size > limit:
            raise ValueError("input exceeds byte limit")
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65536, limit - size + 1))
            if not chunk:
                return b"".join(chunks)
            size += len(chunk)
            if size > limit:
                raise ValueError("input exceeds byte limit")
            chunks.append(chunk)
    finally:
        os.close(descriptor)
