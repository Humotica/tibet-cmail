"""
Sealed Mode (v0.2.x) — AES-256-GCM encrypted cmail envelopes.

Light Mode (v0.1) put the body in clear JSON. Sealed Mode wraps the body
inside an AES-256-GCM ciphertext that is bound to the message_id, sender, and
recipient via authenticated additional data (AAD). Swapping the envelope to a
different recipient or message_id breaks decryption.

Wire-format (`cmail.message.sealed.v1`):

    {
        "kind": "cmail.message.sealed.v1",
        "message_id": "cmail_...",
        "from": "alice.aint",
        "to": "bob.aint",
        "sent_at": "...",
        "content_hash": "sha256:..."   // hash of plaintext body (set BEFORE seal)
        "sealed": {
            "alg": "AES-256-GCM",
            "nonce": "<b64>",
            "ciphertext": "<b64>",     // sealed JSON of { subject, body, body_class }
            "aad": "<b64>"             // canonical "from|to|message_id" string
        }
    }

Note: kind, message_id, from, to are in the clear so a relay/router can route
without decrypting. subject and body live inside ciphertext.

Key management v0.2:
    - 32-byte AES-256 key as 64-char hex string (--key) OR env var (--key-env).
    - Sender and recipient must share the key out-of-band.

Key management v0.3 (planned):
    - JIS-derived bilateral consent keys. PSK becomes a fallback only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from .envelope import CMAIL_KIND, Envelope, hash_body


SEALED_KIND = "cmail.message.sealed.v1"
SEAL_ALG = "AES-256-GCM"
KEY_BYTES = 32   # AES-256 → 32 bytes
NONCE_BYTES = 12  # GCM nonce


class SealedModeUnavailable(RuntimeError):
    """Raised when the `cryptography` library is not installed."""


def _import_aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM
    except ImportError as e:
        raise SealedModeUnavailable(
            "Sealed Mode needs the `cryptography` library. "
            "Install via: pip install 'tibet-cmail[sealed]'"
        ) from e


# ─────────────────────────────────────────────────────────────────
# Key helpers
# ─────────────────────────────────────────────────────────────────


def generate_key() -> str:
    """Return a fresh AES-256 key as 64-char hex string."""
    return secrets.token_hex(KEY_BYTES)


def _key_bytes(key_hex: str) -> bytes:
    """Decode a hex key. Validates length."""
    try:
        b = bytes.fromhex(key_hex)
    except ValueError as e:
        raise ValueError(f"sealed: key must be hex string, got: {e}") from e
    if len(b) != KEY_BYTES:
        raise ValueError(f"sealed: key must be {KEY_BYTES} bytes ({KEY_BYTES*2} hex chars), got {len(b)}")
    return b


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _aad(from_: str, to: str, message_id: str) -> bytes:
    """Canonical AAD: pipe-joined sender/recipient/message_id."""
    return f"{from_}|{to}|{message_id}".encode("utf-8")


# ─────────────────────────────────────────────────────────────────
# Seal / unseal
# ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SealedPayload:
    """A SealedPayload represents the sealed `sealed` sub-object of an envelope."""
    alg: str
    nonce_b64: str
    ciphertext_b64: str
    aad_b64: str

    def to_dict(self) -> dict[str, str]:
        return {
            "alg": self.alg,
            "nonce": self.nonce_b64,
            "ciphertext": self.ciphertext_b64,
            "aad": self.aad_b64,
        }


def seal(
    *,
    plaintext: str,
    key_hex: str,
    from_: str,
    to: str,
    message_id: str,
) -> SealedPayload:
    """Encrypt `plaintext` under AES-256-GCM, bound to (from, to, message_id) via AAD."""
    AESGCM = _import_aesgcm()
    key = _key_bytes(key_hex)
    nonce = secrets.token_bytes(NONCE_BYTES)
    aad = _aad(from_, to, message_id)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
    return SealedPayload(
        alg=SEAL_ALG,
        nonce_b64=_b64(nonce),
        ciphertext_b64=_b64(ciphertext),
        aad_b64=_b64(aad),
    )


def unseal(
    *,
    payload: SealedPayload,
    key_hex: str,
    from_: str,
    to: str,
    message_id: str,
) -> str:
    """Decrypt + verify a sealed payload. AAD-mismatch raises."""
    AESGCM = _import_aesgcm()
    if payload.alg != SEAL_ALG:
        raise ValueError(f"sealed: unsupported alg {payload.alg!r}; expected {SEAL_ALG!r}")
    key = _key_bytes(key_hex)
    nonce = _b64d(payload.nonce_b64)
    ciphertext = _b64d(payload.ciphertext_b64)
    expected_aad = _aad(from_, to, message_id)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, expected_aad)
    return plaintext.decode("utf-8")


# ─────────────────────────────────────────────────────────────────
# Envelope wrapping
# ─────────────────────────────────────────────────────────────────


def build_sealed_envelope(
    *,
    from_: str,
    to: str,
    subject: str,
    body: str,
    key_hex: str,
    body_class: str = "text/plain",
    message_id: Optional[str] = None,
    sent_at: Optional[str] = None,
) -> dict[str, Any]:
    """Build a `cmail.message.sealed.v1` envelope dict ready to JSON-serialise."""
    import uuid
    mid = message_id or f"cmail_{uuid.uuid4().hex[:16]}"
    sent = sent_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    content_hash_plain = hash_body(body)

    plaintext_inner = json.dumps(
        {"subject": subject, "body": body, "body_class": body_class},
        ensure_ascii=False,
    )
    payload = seal(
        plaintext=plaintext_inner,
        key_hex=key_hex,
        from_=from_,
        to=to,
        message_id=mid,
    )

    return {
        "kind": SEALED_KIND,
        "message_id": mid,
        "from": from_,
        "to": to,
        "sent_at": sent,
        "content_hash": content_hash_plain,
        "sealed": payload.to_dict(),
    }


def unseal_envelope(sealed_envelope: dict[str, Any], key_hex: str) -> Envelope:
    """Decrypt a sealed envelope dict back into a plain `Envelope` instance."""
    if sealed_envelope.get("kind") != SEALED_KIND:
        raise ValueError(f"sealed: expected kind={SEALED_KIND!r}, got {sealed_envelope.get('kind')!r}")
    payload = SealedPayload(
        alg=sealed_envelope["sealed"]["alg"],
        nonce_b64=sealed_envelope["sealed"]["nonce"],
        ciphertext_b64=sealed_envelope["sealed"]["ciphertext"],
        aad_b64=sealed_envelope["sealed"]["aad"],
    )
    plaintext_inner = unseal(
        payload=payload,
        key_hex=key_hex,
        from_=sealed_envelope["from"],
        to=sealed_envelope["to"],
        message_id=sealed_envelope["message_id"],
    )
    inner = json.loads(plaintext_inner)
    return Envelope(
        from_=sealed_envelope["from"],
        to=sealed_envelope["to"],
        subject=inner.get("subject", ""),
        body=inner["body"],
        body_class=inner.get("body_class", "text/plain"),
        message_id=sealed_envelope["message_id"],
        sent_at=sealed_envelope.get("sent_at", ""),
        content_hash=sealed_envelope["content_hash"],
        kind=CMAIL_KIND,  # after unseal, treat as Light envelope
    )


def is_sealed_envelope(data: dict[str, Any]) -> bool:
    return isinstance(data, dict) and data.get("kind") == SEALED_KIND


def resolve_key(*, key_arg: Optional[str], key_env: Optional[str]) -> Optional[str]:
    """Pick a key from CLI arg or env var. Returns hex string or None."""
    if key_arg:
        return key_arg
    if key_env:
        return os.environ.get(key_env)
    return None
