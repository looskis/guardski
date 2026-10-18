from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Protocol

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


class Signer(Protocol):
    name: str

    def sign(self, message: bytes) -> str: ...

    def public_key_hex(self) -> str: ...

    def fingerprint(self) -> str: ...


def public_from_private(private_key_hex: str) -> str:
    _require()
    from cryptography.hazmat.primitives import serialization

    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )


class FileSigner:
    """Ed25519 file-key signer; the seam a PKCS#11/HSM signer replaces (decision 2)."""

    name = "file"

    def __init__(self, private_key_hex: str) -> None:
        self._private = private_key_hex

    def sign(self, message: bytes) -> str:
        return sign(self._private, message)

    def public_key_hex(self) -> str:
        return public_from_private(self._private)

    def fingerprint(self) -> str:
        return fingerprint(self.public_key_hex())


def load_signer(config) -> Signer:
    if not AVAILABLE:
        raise SigningUnavailable("the 'cryptography' package is required for signatures")
    provider = getattr(config.signing, "provider", "file")
    if provider != "file":
        raise SigningUnavailable(f"unsupported signer provider: {provider}")
    path = config.signing.private_key_path
    if not path:
        raise SigningUnavailable("signing.private_key_path is not set")
    return FileSigner(Path(path).read_text().strip())
