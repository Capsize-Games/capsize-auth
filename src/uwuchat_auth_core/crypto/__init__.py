"""Cryptographic helpers bundled with the auth core.

* :mod:`uwuchat_auth_core.crypto.data_encryption` — a Fernet keyring with
  key rotation and an optional on-disk edge key.
* :mod:`uwuchat_auth_core.crypto.dek_cache` — the process-local,
  TTL-bound per-user data-encryption-key cache used by the middleware.

Both are imported explicitly (``from uwuchat_auth_core.crypto import
data_encryption``) so this package's ``__init__`` stays import-light.
"""
