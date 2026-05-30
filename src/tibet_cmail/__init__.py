"""
tibet-cmail — capsulated email + command hub for HumoticaOS.

Light Mode (v0.1.x):
    Transport:    I-Poll PUSH (over brain_api at localhost:8000 / api.ainternet.org)
    Envelope:     JSON with from/to/subject/body/sent_at/message_id/content_hash
    Evidence:     cap-bus gateway-event.v1 (intent=cmail.message.sent/received)

Sealed Mode (v0.2.x — future):
    Add TBZ-pack + tibet-continuityd inbox routing + SAM-binding for non-AI recipients.

Three pillars (mirrors `cmail-as-hub` anchor doc):
    INBOX    — read inbound cmails
    COMPOSE  — write + send
    AUDIT    — open trace via cap-bus events

Public API:
    from tibet_cmail.envelope import Envelope, build_envelope, hash_body
    from tibet_cmail.cli import main as cli_main
"""

__version__ = "0.2.5"

from .audit import (
    CMAIL_RECEIVED_INTENT,
    CMAIL_SENT_INTENT,
    DEFAULT_AUDIT_PATH,
    build_received_event,
    build_sent_event,
    log_event,
    try_validate,
)
from .envelope import Envelope, build_envelope, hash_body
from .sealed import (
    SEAL_ALG,
    SEALED_KIND,
    SealedModeUnavailable,
    SealedPayload,
    build_sealed_envelope,
    generate_key,
    is_sealed_envelope,
    seal,
    unseal,
    unseal_envelope,
)

__all__ = [
    "Envelope",
    "build_envelope",
    "hash_body",
    "CMAIL_SENT_INTENT",
    "CMAIL_RECEIVED_INTENT",
    "DEFAULT_AUDIT_PATH",
    "build_sent_event",
    "build_received_event",
    "log_event",
    "try_validate",
    "SEAL_ALG",
    "SEALED_KIND",
    "SealedModeUnavailable",
    "SealedPayload",
    "build_sealed_envelope",
    "generate_key",
    "is_sealed_envelope",
    "seal",
    "unseal",
    "unseal_envelope",
    "__version__",
]
