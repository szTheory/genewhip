"""D131 disposable synthetic writer; serial process-interruption model only.

No production formats, aggregate accounting, concurrent adversary protection or
power-loss durability claim. Each immutable charge file represents one synthetic
charge. Reconstructing Writer and retrying the same identity is recovery.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile


class Rejected(ValueError):
    """Unsafe path, conflicting identity, bytes or persisted synthetic state."""


class Interrupted(RuntimeError):
    """Named process-interruption injection; persisted files remain intact."""


class Writer:
    CHECKPOINTS = (
        "after_intent", "before_publication", "after_publication",
        "before_charge", "after_charge",
    )

    def __init__(self, root):
        self.root = Path(root)
        self._root_check()

    def _root_check(self):
        root = self.root
        temp = Path(tempfile.gettempdir()).resolve()
        if (not root.is_absolute() or root.is_symlink()
                or root.parent.resolve() != temp
                or not root.name.startswith("d131-")
                or not root.is_dir() or root.resolve() != root):
            raise Rejected("root must be a real disposable d131 temporary root")

    def _path(self, name):
        self._root_check()
        path = self.root / name
        if path.is_symlink():
            raise Rejected("symlink rejected")
        return path

    def _read(self, name):
        path = self._path(name)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, "rb") as stream:
            return stream.read()

    def _once(self, name, data):
        path = self._path(name)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            if self._read(name) != data:
                raise Rejected("existing synthetic state conflicts")
            return
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    def transact(self, transaction_id, destination, payload, fail_at=None):
        if (not isinstance(transaction_id, str)
                or re.fullmatch(r"[a-z][a-z0-9-]{0,39}", transaction_id) is None):
            raise Rejected("invalid transaction identity")
        if (not isinstance(destination, str)
                or re.fullmatch(r"[a-z][a-z0-9-]{0,39}\.bin", destination) is None):
            raise Rejected("destination must be a flat synthetic bin name")
        if not isinstance(payload, bytes) or len(payload) > 65536:
            raise Rejected("payload must be bounded bytes")
        if fail_at is not None and fail_at not in self.CHECKPOINTS:
            raise Rejected("unknown interruption checkpoint")

        def checkpoint(name):
            if fail_at == name:
                raise Interrupted(name)

        # Bind the caller identity to exact semantics, rather than trusting an
        # output digest or a caller's claim that a retry is identical.
        intent = json.dumps({"version": 1, "id": transaction_id,
                             "destination": destination, "payload": payload.hex()},
                            sort_keys=True, separators=(",", ":")).encode("ascii")
        prefix = "txn-" + transaction_id
        # Reject redirected paths before creating any intent or charge.
        for name in (destination, prefix + ".intent.json", prefix + ".stage",
                     prefix + ".charge.json"):
            self._path(name)
        self._once(prefix + ".intent.json", intent)
        checkpoint("after_intent")
        existing = self._read(destination)
        if existing is not None and existing != payload:
            raise Rejected("destination bytes conflict")
        self._once(prefix + ".stage", payload)
        checkpoint("before_publication")
        if existing is None:
            try:
                os.link(self._path(prefix + ".stage"), self._path(destination),
                        follow_symlinks=False)
            except FileExistsError:
                if self._read(destination) != payload:
                    raise Rejected("destination bytes conflict")
        if self._read(destination) != payload:
            raise Rejected("publication verification failed")
        checkpoint("after_publication")
        checkpoint("before_charge")
        charge = json.dumps({"id": transaction_id, "units": 1,
                             "intent_sha256": hashlib.sha256(intent).hexdigest()},
                            sort_keys=True, separators=(",", ":")).encode("ascii")
        self._once(prefix + ".charge.json", charge)
        checkpoint("after_charge")
        return "published-and-charged"
