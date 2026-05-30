"""
Cmail audit-trail — gateway-event.v1 emitters for cmail.message.sent/received.

Every cmail action lands as a `gateway-event.v1` record. The events match the
canonical cmail-event fixtures in `tibet-cap-bus 0.1.3+` (`cmail-events.v1.json`)
so a downstream cap-bus consumer can reconstruct the full message journey.

Light Mode v0.1.1 writes events to a local JSONL audit log (default
`~/.cmail/audit.jsonl`). Future versions (0.2.x+) will also POST the event to a
cap-bus runtime when one is reachable. Lazy validation against
`tibet_cap_bus.validate_gateway_event_record` is best-effort: if cap-bus is not
installed, the events are still well-formed and validate-able later.

The shape of the gateway-event.v1 record is fixed; this module only sets the
cmail-specific fields. See `tibet_cap_bus.event_contract` for the canonical
field list.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .envelope import Envelope


# Intent strings — match cap-bus cmail-event fixtures verbatim.
CMAIL_SENT_INTENT = "cmail.message.sent"
CMAIL_RECEIVED_INTENT = "cmail.message.received"

DEFAULT_AUDIT_PATH = Path.home() / ".cmail" / "audit.jsonl"

# Optional cap-bus runtime endpoint — when set, audit events are POSTed there
# *in addition to* the JSONL append. Best-effort: never blocks or fails the send.
CAPBUS_URL_ENV = "CMAIL_CAPBUS_URL"
CAPBUS_POST_TIMEOUT = 2.0  # short, never delays the cmail-send path


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _event_id(prefix: str) -> str:
    return f"evt_{prefix}_{uuid.uuid4().hex[:12]}"


def _operation_id(envelope: Envelope) -> str:
    """One operation per message, derived from the envelope's message_id."""
    return f"op_{envelope.message_id}"


CMAIL_EVENT_KIND = "cmail.message.event.v1"


def _base_event(
    *,
    intent: str,
    envelope: Envelope,
    actor: str,
    status: str,
    latency_ms: float,
    surface: str,
    sealed: bool = False,
    extra_payload: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build a gateway-event.v1 record with cmail-specific fields filled in.

    The top-level `kind` and `sealed` fields are deliberately exposed so that
    downstream evidence-adapters (e.g. tibet-audit) can match without parsing
    the nested payload. `kind` starts with "cmail." so any
    `kind.startswith("cmail.")` filter triggers, and `sealed` lets a consumer
    accurately count Light vs Sealed without falling back to content_hash
    presence.
    """
    payload: dict[str, Any] = {
        "intent": intent,
        "to": envelope.to,
        "envelope_kind": "message",
        "content_hash": envelope.content_hash,
        "sealed": bool(sealed),
    }
    if extra_payload:
        payload.update(extra_payload)

    return {
        # REQUIRED_GATEWAY_FIELDS
        "event_id": _event_id(intent.split(".")[-1]),
        "observation_layer": "tibet-gateway",
        "timestamp": _utcnow_iso(),
        "operation_id": _operation_id(envelope),
        "agent_id": actor,
        "intent": intent,
        "provider": "user-direct",
        "model": "user-direct",
        "route_class": "direct",
        "surface": surface,
        "transport": "ipoll-http",
        "status": status,
        "latency_ms": latency_ms,
        "lane_class": "human-message",
        "lane_collision_policy": "queue",
        "coffee_lane_policy": "sip_anyway",
        "attestation_layer": "jis",
        "_emitter": "tibet-cmail",
        # Useful optional fields (validate as object/string when present)
        "actor_aint": actor,
        "actor_jis_pubkey": None,
        "verified": True,
        "envelope_id": envelope.message_id,
        "content_hash": envelope.content_hash,
        "attestation_ref": f"attest:{envelope.message_id}",
        "gateway_actor": "jis:tibet-cmail",
        # Top-level adapter-friendly fields (0.2.4+):
        "kind": CMAIL_EVENT_KIND,
        "sealed": bool(sealed),
        "payload": payload,
    }


def build_sent_event(
    envelope: Envelope, latency_ms: float = 0.0, sealed: bool = False,
) -> dict[str, Any]:
    """gateway-event.v1 record for an outbound cmail."""
    return _base_event(
        intent=CMAIL_SENT_INTENT,
        envelope=envelope,
        actor=envelope.from_,
        status="cmail-pushed",
        latency_ms=latency_ms,
        surface=f"cmail.sent:{envelope.to}",
        sealed=sealed,
    )


def build_received_event(
    envelope: Envelope, recipient: str, sealed: bool = False,
) -> dict[str, Any]:
    """gateway-event.v1 record for an inbound cmail observation."""
    return _base_event(
        intent=CMAIL_RECEIVED_INTENT,
        envelope=envelope,
        actor=recipient,
        status="cmail-observed",
        latency_ms=0.0,
        surface=f"cmail.received:{recipient}",
        sealed=sealed,
        extra_payload={"from": envelope.from_},
    )


def log_event(event: dict[str, Any], path: Optional[Path | str] = None) -> Path:
    """Append a gateway-event.v1 record to the local JSONL audit log.

    Creates the parent directory if needed. Returns the path that was written
    so callers can show it to the user.

    Side-effect: if env var CMAIL_CAPBUS_URL is set, the event is *also*
    POSTed to that endpoint (best-effort, never raises). This lets a cap-bus
    runtime stream cmail events as they happen instead of waiting for an
    out-of-band log scrape.
    """
    target = Path(path) if path is not None else DEFAULT_AUDIT_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    _maybe_post_to_capbus(event)
    return target


def _maybe_post_to_capbus(event: dict[str, Any]) -> None:
    """Optional POST to a cap-bus runtime endpoint. Best-effort, swallows errors.

    The endpoint shape is intentionally loose: any service that accepts a
    POST of a gateway-event.v1 JSON record at <url>/event qualifies. A small
    timeout (2 s) means an offline endpoint never stalls the send pipeline.
    """
    base = os.environ.get(CAPBUS_URL_ENV)
    if not base:
        return
    url = f"{base.rstrip('/')}/event"
    try:
        body = json.dumps(event, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "tibet-cmail-audit/0.2.2",
            },
        )
        with urllib.request.urlopen(req, timeout=CAPBUS_POST_TIMEOUT):
            pass
    except Exception:  # noqa: BLE001 — best-effort, audit-log is source of truth
        pass


def try_validate(event: dict[str, Any]) -> list[str]:
    """Best-effort validation against `tibet_cap_bus.validate_gateway_event_record`.

    Returns a list of error strings (empty = pass, or = "cap-bus not installed").
    Never raises: the audit-log is the source of truth; validation is for tests/CI.
    """
    try:
        from tibet_cap_bus import validate_gateway_event_record  # type: ignore
    except ImportError:
        return []
    try:
        return list(validate_gateway_event_record(event))
    except Exception as e:  # pragma: no cover — pathological
        return [f"validation raised: {e!r}"]
