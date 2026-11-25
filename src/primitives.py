"""Canonical serialization and Ed25519 helpers for D3-13.

Self-contained: this module does NOT import from agent-exec-binding-mvp.
It re-implements the MVP's canonical_json/digest_object byte-for-byte so the
E2.2 baseline can be replayed faithfully, then adds a small Ed25519 wrapper.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def canonical_json(value: Any) -> bytes:
    """Deterministic JSON bytes, identical to the MVP commitment encoding."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_object(value: Any) -> str:
    """H(canon(value)) with H = SHA-256, hex encoded."""
    return sha256_hex(canonical_json(value))


class Ed25519Signer:
    """A signing capability. Whoever holds this object holds the private key."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        self._sk = private_key if private_key is not None else Ed25519PrivateKey.generate()

    @classmethod
    def generate(cls) -> "Ed25519Signer":
        return cls()

    def public_key_raw(self) -> bytes:
        return self._sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key_raw()).decode("ascii")

    def private_key_b64(self) -> str:
        return base64.b64encode(
            self._sk.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()
            )
        ).decode("ascii")

    def sign_b64(self, value: Any) -> str:
        return base64.b64encode(self._sk.sign(canonical_json(value))).decode("ascii")


def verify_b64(public_key_raw: bytes, signature_b64: str, value: Any) -> bool:
    """Verify a base64 Ed25519 signature over canonical_json(value)."""
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(
            signature, canonical_json(value)
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)
