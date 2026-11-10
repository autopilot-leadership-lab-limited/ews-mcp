"""Zero-knowledge storage of Exchange passwords (hosted mode).

The server must not be able to read a stored password on its own. Each OAuth
grant (one AI app's connection) gets an X25519 key pair:

* Passwords are *sealed* to the grant's public key (ephemeral X25519 + HKDF +
  AES-GCM). Anyone with the public key can seal, so the server can add a
  mailbox or update a password later without being able to read it back.
* The grant's private key is stored only *wrapped* under keys derived from the
  OAuth tokens the AI app holds (the authorization code, then the access and
  refresh tokens). The database keeps only SHA-256 hashes of those tokens, so
  the database and the master key together still open nothing.

A password is therefore readable only while a request carries a valid token
from that AI app: in memory, for that request. This is verifiable trust in the
running code, not a technical impossibility: whoever runs the server could
change the code to log passwords. The code is public and deployments are
pinned to a commit, which `/health` reports.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_WRAP_INFO = b"ews-mcp grant key wrap v1"
_SEAL_INFO = b"ews-mcp seal v1"
_RAW = serialization.Encoding.Raw


class SealError(Exception):
    """A wrapped key or sealed secret could not be opened (wrong token, tampering)."""


def _hkdf(material: bytes, *, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(material)


def new_key_pair() -> tuple[bytes, bytes]:
    """Return (private_key_bytes, public_key_bytes), 32 bytes each."""
    priv = X25519PrivateKey.generate()
    return (
        priv.private_bytes(_RAW, serialization.PrivateFormat.Raw, serialization.NoEncryption()),
        priv.public_key().public_bytes(_RAW, serialization.PublicFormat.Raw),
    )


def wrap_key(private_key: bytes, token: str, *, context: str) -> bytes:
    """Encrypt a grant private key under a key derived from an OAuth token."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    kek = _hkdf(token.encode(), salt=salt, info=_WRAP_INFO)
    return salt + nonce + AESGCM(kek).encrypt(nonce, private_key, context.encode())


def unwrap_key(blob: bytes, token: str, *, context: str) -> bytes:
    if len(blob) < 28:
        raise SealError("wrapped key too short")
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    kek = _hkdf(token.encode(), salt=salt, info=_WRAP_INFO)
    try:
        return AESGCM(kek).decrypt(nonce, ct, context.encode())
    except Exception as exc:  # InvalidTag
        raise SealError("wrapped key does not open with this token") from exc


def seal(public_key: bytes, plaintext: str, *, context: str) -> bytes:
    """Encrypt `plaintext` so only the holder of the matching private key can read it."""
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(_RAW, serialization.PublicFormat.Raw)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(public_key))
    key = _hkdf(shared, salt=eph_pub + public_key, info=_SEAL_INFO)
    nonce = os.urandom(12)
    return eph_pub + nonce + AESGCM(key).encrypt(nonce, plaintext.encode(), context.encode())


def open_sealed(private_key: bytes, blob: bytes, *, context: str) -> str:
    if len(blob) < 44:
        raise SealError("sealed secret too short")
    eph_pub, nonce, ct = blob[:32], blob[32:44], blob[44:]
    priv = X25519PrivateKey.from_private_bytes(private_key)
    pub = priv.public_key().public_bytes(_RAW, serialization.PublicFormat.Raw)
    shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    key = _hkdf(shared, salt=eph_pub + pub, info=_SEAL_INFO)
    try:
        return AESGCM(key).decrypt(nonce, ct, context.encode()).decode()
    except Exception as exc:
        raise SealError("sealed secret does not open with this key") from exc
