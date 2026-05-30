"""Tests for tibet_cmail.sealed — AES-256-GCM envelopes with AAD-binding."""

from __future__ import annotations

import pytest

from tibet_cmail.sealed import (
    SEALED_KIND,
    SealedPayload,
    build_sealed_envelope,
    generate_key,
    is_sealed_envelope,
    resolve_key,
    seal,
    unseal,
    unseal_envelope,
)


def test_generate_key_is_64_hex_chars():
    k = generate_key()
    assert len(k) == 64
    int(k, 16)  # parses


def test_generate_key_is_random():
    assert generate_key() != generate_key()


def test_seal_unseal_roundtrip():
    k = generate_key()
    payload = seal(
        plaintext="hello",
        key_hex=k,
        from_="a.aint", to="b.aint", message_id="m1",
    )
    assert isinstance(payload, SealedPayload)
    decrypted = unseal(
        payload=payload, key_hex=k,
        from_="a.aint", to="b.aint", message_id="m1",
    )
    assert decrypted == "hello"


def test_unseal_with_wrong_recipient_fails():
    """AAD binds the envelope to (from, to, message_id); flipping `to` breaks."""
    k = generate_key()
    payload = seal(plaintext="hi", key_hex=k, from_="a", to="b", message_id="m")
    with pytest.raises(Exception):
        unseal(payload=payload, key_hex=k, from_="a", to="c", message_id="m")


def test_unseal_with_wrong_sender_fails():
    k = generate_key()
    payload = seal(plaintext="hi", key_hex=k, from_="a", to="b", message_id="m")
    with pytest.raises(Exception):
        unseal(payload=payload, key_hex=k, from_="x", to="b", message_id="m")


def test_unseal_with_wrong_message_id_fails():
    k = generate_key()
    payload = seal(plaintext="hi", key_hex=k, from_="a", to="b", message_id="m")
    with pytest.raises(Exception):
        unseal(payload=payload, key_hex=k, from_="a", to="b", message_id="other")


def test_unseal_with_wrong_key_fails():
    k1 = generate_key()
    k2 = generate_key()
    payload = seal(plaintext="hi", key_hex=k1, from_="a", to="b", message_id="m")
    with pytest.raises(Exception):
        unseal(payload=payload, key_hex=k2, from_="a", to="b", message_id="m")


def test_short_key_raises():
    with pytest.raises(ValueError, match="key must be"):
        seal(plaintext="x", key_hex="abc", from_="a", to="b", message_id="m")


def test_non_hex_key_raises():
    with pytest.raises(ValueError, match="key must be hex"):
        seal(plaintext="x", key_hex="z" * 64, from_="a", to="b", message_id="m")


def test_envelope_roundtrip_carries_subject_body_and_class():
    k = generate_key()
    env_dict = build_sealed_envelope(
        from_="alice.aint",
        to="bob.aint",
        subject="Re: lunch?",
        body="12:30",
        key_hex=k,
        body_class="text/plain",
    )
    assert env_dict["kind"] == SEALED_KIND
    assert env_dict["from"] == "alice.aint"
    assert env_dict["to"] == "bob.aint"
    assert "sealed" in env_dict
    assert env_dict["sealed"]["alg"] == "AES-256-GCM"

    unsealed = unseal_envelope(env_dict, k)
    assert unsealed.from_ == "alice.aint"
    assert unsealed.to == "bob.aint"
    assert unsealed.subject == "Re: lunch?"
    assert unsealed.body == "12:30"
    assert unsealed.body_class == "text/plain"
    assert unsealed.content_hash == env_dict["content_hash"]
    assert unsealed.verify() is True


def test_envelope_carries_nonascii():
    k = generate_key()
    env_dict = build_sealed_envelope(
        from_="alice.aint",
        to="bob.aint",
        subject="Réservé",
        body="Bonjour 👋",
        key_hex=k,
    )
    unsealed = unseal_envelope(env_dict, k)
    assert unsealed.subject == "Réservé"
    assert unsealed.body == "Bonjour 👋"


def test_unseal_envelope_with_wrong_key_fails():
    k_right = generate_key()
    k_wrong = generate_key()
    env_dict = build_sealed_envelope(
        from_="a", to="b", subject="s", body="body", key_hex=k_right,
    )
    with pytest.raises(Exception):
        unseal_envelope(env_dict, k_wrong)


def test_is_sealed_envelope_detection():
    assert is_sealed_envelope({"kind": SEALED_KIND}) is True
    assert is_sealed_envelope({"kind": "cmail.message.v1"}) is False
    assert is_sealed_envelope({"no_kind": True}) is False
    assert is_sealed_envelope("not even a dict") is False


def test_resolve_key_prefers_arg(monkeypatch):
    monkeypatch.setenv("MY_KEY", "envkey")
    assert resolve_key(key_arg="argkey", key_env="MY_KEY") == "argkey"


def test_resolve_key_falls_back_to_env(monkeypatch):
    monkeypatch.setenv("MY_KEY", "envkey")
    assert resolve_key(key_arg=None, key_env="MY_KEY") == "envkey"


def test_resolve_key_returns_none_when_nothing_set(monkeypatch):
    monkeypatch.delenv("MY_KEY", raising=False)
    assert resolve_key(key_arg=None, key_env="MY_KEY") is None
    assert resolve_key(key_arg=None, key_env=None) is None


def test_content_hash_is_of_plaintext():
    """content_hash on the sealed envelope must match hashing the unsealed body."""
    from tibet_cmail.envelope import hash_body
    k = generate_key()
    env_dict = build_sealed_envelope(
        from_="a", to="b", subject="s", body="HELLO", key_hex=k,
    )
    assert env_dict["content_hash"] == hash_body("HELLO")


def test_explicit_message_id_honored():
    k = generate_key()
    env_dict = build_sealed_envelope(
        from_="a", to="b", subject="s", body="x", key_hex=k,
        message_id="cmail_pinned_42",
    )
    assert env_dict["message_id"] == "cmail_pinned_42"
    # AAD-binding works with the pinned id
    unsealed = unseal_envelope(env_dict, k)
    assert unsealed.message_id == "cmail_pinned_42"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
