from __future__ import annotations

import hashlib

try:  # Ed25519 via the `cryptography` library; no vendored crypto (SPEC §5.1).
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when the dependency is absent
    AVAILABLE = False


class SigningUnavailable(RuntimeError):
    pass


def _require() -> None:
    if not AVAILABLE:
        raise SigningUnavailable("the 'cryptography' package is required for signatures")


def generate_keypair() -> tuple[str, str]:
    _require()
    private = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization

    private_hex = private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    ).hex()
    public_hex = (
        private.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    return private_hex, public_hex


def sign(private_key_hex: str, message: bytes) -> str:
    _require()
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return key.sign(message).hex()


def verify(public_key_hex: str, signature_hex: str, message: bytes) -> bool:
    _require()
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    try:
        key.verify(bytes.fromhex(signature_hex), message)
        return True
    except Exception:
        return False


def fingerprint(public_key_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:16]
