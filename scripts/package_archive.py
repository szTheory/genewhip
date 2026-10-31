"""Bound tar header work before tarfile builds a member index."""
import gzip
import io
import tarfile

BLOCK = 512
MAX_EXTENDED_HEADER = 64 * 1024
MAX_EXTENSION_CHAIN = 128


def _number(field):
    return tarfile.nti(field)


def _pax_size(payload):
    values = {}
    offset = 0
    while offset < len(payload):
        space = payload.find(b" ", offset)
        if space < 0:
            raise ValueError("archive-pax-record-invalid")
        try:
            length = int(payload[offset:space])
        except ValueError as error:
            raise ValueError("archive-pax-record-invalid") from error
        end = offset + length
        if length <= space - offset + 1 or end > len(payload) or payload[end - 1:end] != b"\n":
            raise ValueError("archive-pax-record-invalid")
        record = payload[space + 1:end - 1]
        key, separator, value = record.partition(b"=")
        if not separator:
            raise ValueError("archive-pax-record-invalid")
        if key == b"size":
            values[key] = value
        offset = end
    return values


def preflight_tar_gz(source, *, max_members, max_expanded_bytes):
    """Count and size-check members incrementally, bounding PAX/GNU headers too."""
    if isinstance(source, (bytes, bytearray)):
        raw = io.BytesIO(source)
    else:
        raw = open(source, "rb")
    try:
        with gzip.GzipFile(fileobj=raw, mode="rb") as stream:
            count = expanded = extension_count = 0
            pending_size = None
            global_size = None
            while True:
                header = stream.read(BLOCK)
                if not header or header == bytes(BLOCK):
                    break
                if len(header) != BLOCK:
                    raise ValueError("archive-header-truncated")
                # Count physical headers and all decompressed bytes, including
                # extension payload/padding, before handing this archive to
                # tarfile (whose PAX chaining is recursive).
                count += 1
                expanded += BLOCK
                if count > max_members:
                    raise ValueError("archive-member-count-limit")
                if expanded > max_expanded_bytes:
                    raise ValueError("archive-expanded-size-limit")
                kind = header[156:157]
                size = _number(header[124:136])
                if size < 0:
                    raise ValueError("archive-member-size-invalid")
                if kind in (b"x", b"g", b"L", b"K"):
                    extension_count += 1
                    if extension_count > MAX_EXTENSION_CHAIN:
                        raise ValueError("archive-extension-chain-limit")
                    if size > MAX_EXTENDED_HEADER:
                        raise ValueError("archive-extended-header-limit")
                    padding = (-size) % BLOCK
                    expanded += size + padding
                    if expanded > max_expanded_bytes:
                        raise ValueError("archive-expanded-size-limit")
                    payload = stream.read(size)
                    if len(payload) != size:
                        raise ValueError("archive-extended-header-truncated")
                    if padding and len(stream.read(padding)) != padding:
                        raise ValueError("archive-header-truncated")
                    if kind in (b"x", b"g"):
                        pax = _pax_size(payload)
                        if b"size" in pax:
                            try:
                                parsed = int(pax[b"size"])
                            except ValueError as error:
                                raise ValueError("archive-member-size-invalid") from error
                            if parsed < 0 or parsed > max_expanded_bytes:
                                raise ValueError("archive-expanded-size-limit")
                            if kind == b"g":
                                global_size = parsed
                            else:
                                pending_size = parsed
                    continue
                effective_size = pending_size if pending_size is not None else global_size
                if effective_size is None:
                    effective_size = size
                pending_size = None
                if effective_size < 0 or effective_size > max_expanded_bytes:
                    raise ValueError("archive-expanded-size-limit")
                padding = (-effective_size) % BLOCK
                expanded += effective_size + padding
                if expanded > max_expanded_bytes:
                    raise ValueError("archive-expanded-size-limit")
                if effective_size:
                    skipped = 0
                    remaining = effective_size + padding
                    while remaining:
                        chunk = stream.read(min(BLOCK * 128, remaining))
                        if not chunk:
                            raise ValueError("archive-member-truncated")
                        skipped += len(chunk)
                        remaining -= len(chunk)
                if not header[0:100].rstrip(b"\0"):
                    raise ValueError("archive-member-name-empty")
            return count, expanded
    except (OSError, EOFError, tarfile.TarError) as error:
        raise ValueError("archive-malformed") from error
    finally:
        raw.close()
