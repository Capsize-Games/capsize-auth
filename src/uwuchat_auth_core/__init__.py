"""``uwuchat-auth-core`` — reusable auth primitives.

A self-contained extraction of the JWT / password / OAuth / session
primitives that were previously entangled with a specific application's
database and multi-tenant machinery.  The only integration point is
:class:`uwuchat_auth_core.storage.AuthStorageBackend`, which a consuming
application implements and installs with
:func:`uwuchat_auth_core.storage.set_backend`.

Only the lightweight, dependency-free storage seam is re-exported here;
submodules (``jwt``, ``passwords``, ``oauth``, ``middleware``, ...) are
imported explicitly so that importing the package never requires the
environment a particular submodule validates at import time.
"""

from __future__ import annotations

from uwuchat_auth_core.storage import (
    AuthCoreNotConfigured,
    AuthStorageBackend,
    clear_backend,
    get_backend,
    set_backend,
)

__version__ = "0.1.0"

__all__ = [
    "AuthCoreNotConfigured",
    "AuthStorageBackend",
    "__version__",
    "clear_backend",
    "get_backend",
    "set_backend",
]
