"""
tibet-cmail — command-line interface (Light Mode, v0.1).

Commands:
    tibet-cmail send <to> <subject> <body> --from <agent>
                                          send a cmail via I-Poll (Light Mode)
    tibet-cmail inbox <agent>             list inbound cmails (preview)
    tibet-cmail read <agent> <msg-id>     read one cmail body in full
    tibet-cmail status                    backend status

Routing (mirrors ipoll discipline):
    --local       http://localhost:8000          your local brain_api
    --ainternet   https://api.ainternet.org      primary public hub
    --brein       https://brein.jaspervandemeent.nl  secondary fallback

Light Mode = no encryption. Sealed Mode (v0.2.x) will add TBZ + continuityd routing.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Optional

import time

from . import __version__
from .audit import (
    DEFAULT_AUDIT_PATH,
    build_received_event,
    build_sent_event,
    log_event,
)
from .envelope import CMAIL_KIND, Envelope, build_envelope
from .sealed import (
    SEALED_KIND,
    SealedModeUnavailable,
    build_sealed_envelope,
    generate_key,
    is_sealed_envelope,
    resolve_key,
    unseal_envelope,
)


LOCAL_URL = "http://localhost:8000"
AINTERNET_URL = "https://api.ainternet.org"
BREIN_URL = "https://brein.jaspervandemeent.nl"
DEFAULT_URL = os.environ.get("CMAIL_API_URL", LOCAL_URL)
_USER_AGENT = f"tibet-cmail/{__version__}"


def _is_connection_refused(exc: BaseException) -> bool:
    cause = exc.__cause__ or exc.__context__
    while cause is not None:
        if isinstance(cause, ConnectionRefusedError):
            return True
        cause = cause.__cause__ or cause.__context__
    if isinstance(exc, urllib.error.URLError):
        return isinstance(getattr(exc, "reason", None), ConnectionRefusedError)
    return isinstance(exc, ConnectionRefusedError)


def _is_timeout(exc: BaseException) -> bool:
    """True if the underlying cause is a socket timeout (not the same as TCP refused)."""
    if isinstance(exc, TimeoutError):
        return True
    cause = exc.__cause__ or exc.__context__
    while cause is not None:
        if isinstance(cause, TimeoutError):
            return True
        cause = cause.__cause__ or cause.__context__
    return False


def _explain_unreachable(url: str, exc: BaseException) -> str:
    if _is_connection_refused(exc):
        return (
            f"tibet-cmail: backend at {url} is not running (connection refused).\n"
            f"  - Start a local brain_api on port 8000 (private/fast), or\n"
            f"  - retry with --ainternet for the public hub ({AINTERNET_URL}), or\n"
            f"  - retry with --brein for the secondary fallback ({BREIN_URL}), or\n"
            f"  - set CMAIL_API_URL / use --url <host>:<port>."
        )
    if _is_timeout(exc):
        return (
            f"tibet-cmail: backend at {url} did not respond within timeout.\n"
            f"  - Server may be overloaded or stalled; retry with --timeout 30, or\n"
            f"  - retry with --ainternet / --brein for a different backend."
        )
    reason = getattr(exc, "reason", exc)
    return f"tibet-cmail: cannot reach {url}: {reason}"


def _get_json(url: str, timeout: float = 5.0) -> dict[str, Any]:
    req = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": _USER_AGENT},
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _post_json(url: str, payload: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def cmd_send(args: argparse.Namespace) -> int:
    """Send a cmail via I-Poll PUSH (Light or Sealed Mode)."""
    sealed_mode = bool(args.sealed)
    key_hex = resolve_key(key_arg=args.key, key_env=args.key_env) if sealed_mode else None
    if sealed_mode and not key_hex:
        print(
            "tibet-cmail: --sealed requires --key <hex> or --key-env <ENV_NAME>.\n"
            "  Generate one with: tibet-cmail keygen",
            file=sys.stderr,
        )
        return 6

    if sealed_mode:
        try:
            sealed_env = build_sealed_envelope(
                from_=args.from_agent,
                to=args.to,
                subject=args.subject,
                body=args.body,
                key_hex=key_hex,
            )
        except SealedModeUnavailable as e:
            print(f"tibet-cmail: {e}", file=sys.stderr)
            return 7
        # Build a matching Envelope for audit purposes (plaintext hash + ids).
        audit_envelope = Envelope(
            from_=sealed_env["from"],
            to=sealed_env["to"],
            subject=args.subject,
            body=args.body,
            message_id=sealed_env["message_id"],
            sent_at=sealed_env["sent_at"],
            content_hash=sealed_env["content_hash"],
        )
        envelope = audit_envelope
        content_str = json.dumps(sealed_env, ensure_ascii=False)
    else:
        envelope = build_envelope(
            from_=args.from_agent,
            to=args.to,
            subject=args.subject,
            body=args.body,
        )
        content_str = envelope.to_json()

    payload = {
        "from_agent": envelope.from_,
        "to_agent": envelope.to,
        "content": content_str,
        "poll_type": "PUSH",
    }
    url = f"{args.url.rstrip('/')}/api/ipoll/push"
    t0 = time.perf_counter()
    try:
        data = _post_json(url, payload, timeout=args.timeout)
    except urllib.error.HTTPError as e:
        print(f"tibet-cmail: send failed: HTTP {e.code}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(_explain_unreachable(args.url, e), file=sys.stderr)
        return 2
    latency_ms = (time.perf_counter() - t0) * 1000.0

    # Emit + log a gateway-event.v1 (cmail.message.sent) audit record.
    audit_path = None
    audit_err = None
    if not args.no_audit:
        try:
            event = build_sent_event(envelope, latency_ms=latency_ms, sealed=sealed_mode)
            if sealed_mode:
                event["payload"]["sealed_alg"] = "AES-256-GCM"
            audit_path = log_event(event, args.audit_log)
        except Exception as e:  # never let audit break a send
            audit_err = str(e)

    if args.json:
        print(json.dumps({
            "envelope": envelope.to_dict(),
            "i_poll": data,
            "audit_log": str(audit_path) if audit_path else None,
        }, indent=2, ensure_ascii=False))
        return 0

    poll_id = data.get("id") or data.get("poll_id") or "?"
    mode_label = "Sealed (AES-256-GCM)" if sealed_mode else "Light"
    print(f"cmail sent ({mode_label}): {envelope.message_id}")
    print(f"  from={envelope.from_}  to={envelope.to}")
    print(f"  subject: {envelope.subject}")
    print(f"  content_hash: {envelope.content_hash}")
    print(f"  latency: {latency_ms:.1f}ms")
    print(f"  i-poll envelope: {poll_id}")
    if audit_path:
        intent_label = "cmail.message.sent" + (" + sealed=true" if sealed_mode else "")
        print(f"  audit: {audit_path} (gateway-event.v1: {intent_label})")
    elif audit_err:
        print(f"  audit: SKIPPED ({audit_err})")
    return 0


def _is_cmail_envelope(content_str: str) -> bool:
    """Heuristic: True if I-Poll PUSH content looks like a cmail (Light or Sealed)."""
    try:
        d = json.loads(content_str)
    except (ValueError, TypeError):
        return False
    if not isinstance(d, dict):
        return False
    return d.get("kind") in (CMAIL_KIND, SEALED_KIND)


def _parse_cmail_content(content_str: str) -> Optional[dict]:
    """Parse I-Poll content into a cmail-envelope dict, or None if it isn't one."""
    try:
        d = json.loads(content_str)
    except (ValueError, TypeError):
        return None
    return d if isinstance(d, dict) and d.get("kind") in (CMAIL_KIND, SEALED_KIND) else None


def _fetch_polls(args: argparse.Namespace, mark_read: bool) -> tuple[int, list[dict]]:
    url = (
        f"{args.url.rstrip('/')}/api/ipoll/pull/{args.agent}"
        f"?mark_read={'true' if mark_read else 'false'}"
    )
    try:
        data = _get_json(url, timeout=args.timeout)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"tibet-cmail: agent '{args.agent}' not found", file=sys.stderr)
            return 4, []
        if e.code == 401:
            print(
                f"tibet-cmail: inbox-pull requires authentication at this backend (HTTP 401). "
                f"Use --local with a brain_api you control.",
                file=sys.stderr,
            )
            return 5, []
        print(f"tibet-cmail: pull failed: HTTP {e.code}", file=sys.stderr)
        return 1, []
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(_explain_unreachable(args.url, e), file=sys.stderr)
        return 2, []
    return 0, data.get("polls", [])


def cmd_inbox(args: argparse.Namespace) -> int:
    """List inbound cmails (Light + Sealed); filters non-cmail I-Polls out."""
    rc, polls = _fetch_polls(args, mark_read=False)
    if rc != 0:
        return rc

    # Cmail rows: (display_envelope, is_sealed). For sealed-without-key we keep
    # the metadata visible so users see who/when even before they decrypt.
    rows: list[tuple[Envelope, bool]] = []
    for p in polls:
        content = p.get("content", "")
        d = _parse_cmail_content(content)
        if d is None:
            continue
        if is_sealed_envelope(d):
            try:
                shell = Envelope(
                    from_=d["from"],
                    to=d["to"],
                    subject="(sealed)",
                    body="",
                    message_id=d["message_id"],
                    sent_at=d.get("sent_at", ""),
                    content_hash=d.get("content_hash", ""),
                )
                rows.append((shell, True))
            except Exception:
                continue
        else:
            try:
                rows.append((Envelope.from_json(content), False))
            except Exception:
                continue

    # Emit + log a gateway-event.v1 (cmail.message.received) per observed cmail.
    audit_events = 0
    if not args.no_audit and rows:
        for env, sealed_row in rows:
            try:
                event = build_received_event(env, recipient=args.agent, sealed=sealed_row)
                log_event(event, args.audit_log)
                audit_events += 1
            except Exception:
                pass

    if args.json:
        out = []
        for env, sealed in rows:
            d = env.to_dict()
            d["sealed"] = sealed
            out.append(d)
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0

    if not rows:
        non_cmail = len(polls)
        print(f"  (no cmails for {args.agent}; {non_cmail} non-cmail I-Poll(s) skipped)")
        return 0
    print(f"inbox for {args.agent} ({len(rows)} cmail{'s' if len(rows) != 1 else ''}):")
    for env, sealed in rows:
        mode = "[SEALED]" if sealed else "[ LIGHT]"
        subject = env.subject or "(no subject)"
        if len(subject) > 50:
            subject = subject[:47] + "..."
        print(f"  {mode}  [{env.message_id}]  from={env.from_:<18}  {subject}")
    if audit_events:
        print(f"  ({audit_events} cmail.message.received audit event(s) logged)")
    return 0


def cmd_read(args: argparse.Namespace) -> int:
    """Read one cmail by message_id. Auto-unseals if it is sealed AND a key is given."""
    rc, polls = _fetch_polls(args, mark_read=False)
    if rc != 0:
        return rc
    for p in polls:
        content = p.get("content", "")
        d = _parse_cmail_content(content)
        if d is None or d.get("message_id") != args.message_id:
            continue

        if is_sealed_envelope(d):
            key_hex = resolve_key(key_arg=args.key, key_env=args.key_env)
            if not key_hex:
                print(
                    f"tibet-cmail: cmail {args.message_id!r} is SEALED; pass --key <hex> "
                    f"or --key-env <ENV_NAME> to decrypt.\n"
                    f"  from={d['from']}  to={d['to']}  sent={d.get('sent_at','?')}\n"
                    f"  hash(plain)={d.get('content_hash','?')}",
                    file=sys.stderr,
                )
                return 8
            try:
                e = unseal_envelope(d, key_hex)
            except Exception as exc:
                print(f"tibet-cmail: unseal failed: {exc}", file=sys.stderr)
                return 9
            sealed_label = " (unsealed)"
        else:
            e = Envelope.from_json(content)
            sealed_label = ""

        if args.json:
            print(e.to_json(indent=2))
        else:
            print(f"From:    {e.from_}")
            print(f"To:      {e.to}")
            print(f"Sent:    {e.sent_at}")
            print(f"Subject: {e.subject}{sealed_label}")
            print(f"Hash:    {e.content_hash} ({'verified' if e.verify() else 'MISMATCH'})")
            print()
            print(e.body)
        return 0
    print(f"tibet-cmail: no cmail with message_id '{args.message_id}' in {args.agent}'s inbox",
          file=sys.stderr)
    return 4


def cmd_keygen(args: argparse.Namespace) -> int:
    """Generate a fresh 32-byte AES-256 key (64-char hex)."""
    try:
        k = generate_key()
    except SealedModeUnavailable as e:
        print(f"tibet-cmail: {e}", file=sys.stderr)
        return 7
    if args.json:
        print(json.dumps({"alg": "AES-256-GCM", "key_hex": k, "length_bytes": 32}, indent=2))
    else:
        print(k)
        print(f"# 32-byte AES-256 key for tibet-cmail Sealed Mode", file=sys.stderr)
        print(f"# share out-of-band with the recipient (v0.3.x will derive via JIS)", file=sys.stderr)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    url = f"{args.url.rstrip('/')}/api/ipoll/status"
    try:
        data = _get_json(url, timeout=args.timeout)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(_explain_unreachable(args.url, e), file=sys.stderr)
        return 2
    print(f"tibet-cmail backend: {args.url}")
    print(f"  transport status:  {data.get('status', 'unknown')}")
    print(f"  cmail mode:        Light (I-Poll transport, no seal)")
    print(f"  envelope kind:     {CMAIL_KIND}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tibet-cmail",
        description="Cmail — capsulated email + command hub. Light Mode (I-Poll transport).",
    )
    parser.add_argument("--url", default=DEFAULT_URL,
                        help=f"backend URL (default: {DEFAULT_URL}; env CMAIL_API_URL overrides)")
    parser.add_argument("--local", action="store_true",
                        help=f"shortcut for --url {LOCAL_URL}")
    parser.add_argument("--ainternet", action="store_true",
                        help=f"shortcut for --url {AINTERNET_URL}")
    parser.add_argument("--brein", action="store_true",
                        help=f"shortcut for --url {BREIN_URL}")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="HTTP timeout in seconds (default: 5.0)")
    parser.add_argument("--json", action="store_true",
                        help="emit raw JSON instead of human output")
    parser.add_argument("--no-audit", action="store_true",
                        help="skip the gateway-event.v1 audit-log append")
    parser.add_argument("--audit-log", default=None,
                        help=f"path to the cmail audit-log (default: {DEFAULT_AUDIT_PATH})")
    parser.add_argument("--version", action="version", version=f"tibet-cmail {__version__}")

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_send = sub.add_parser("send", help="send a cmail via I-Poll (Light Mode)")
    p_send.add_argument("to", help="recipient .aint agent")
    p_send.add_argument("subject", help="cmail subject line")
    p_send.add_argument("body", help="cmail body (use quotes for multi-word)")
    p_send.add_argument("--from", dest="from_agent", required=True,
                        help="sender agent id")
    # Sealed Mode (0.2.0+) — only relevant for send.
    p_send.add_argument("--sealed", action="store_true",
                        help="use Sealed Mode (AES-256-GCM); requires --key or --key-env")
    p_send.add_argument("--key", default=None,
                        help="32-byte AES key as 64-char hex (Sealed Mode)")
    p_send.add_argument("--key-env", default=None,
                        help="env var name holding the hex key (Sealed Mode)")
    p_send.set_defaults(func=cmd_send)

    p_inbox = sub.add_parser("inbox", help="list inbound cmails (preview, no mark-read)")
    p_inbox.add_argument("agent", help="agent name (without .aint suffix)")
    p_inbox.set_defaults(func=cmd_inbox)

    p_read = sub.add_parser("read", help="read one cmail in full by message_id; auto-unseals if --key given")
    p_read.add_argument("agent", help="recipient agent name")
    p_read.add_argument("message_id", help="cmail message_id (cmail_<hex>)")
    p_read.add_argument("--key", default=None,
                        help="32-byte AES key as 64-char hex (for sealed cmails)")
    p_read.add_argument("--key-env", default=None,
                        help="env var name holding the hex key (for sealed cmails)")
    p_read.set_defaults(func=cmd_read)

    p_status = sub.add_parser("status", help="show backend + cmail-mode status")
    p_status.set_defaults(func=cmd_status)

    p_keygen = sub.add_parser("keygen", help="generate a fresh AES-256 key for Sealed Mode")
    p_keygen.set_defaults(func=cmd_keygen)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "local", False):
        args.url = LOCAL_URL
    elif getattr(args, "ainternet", False):
        args.url = AINTERNET_URL
    elif getattr(args, "brein", False):
        args.url = BREIN_URL
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
