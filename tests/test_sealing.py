from __future__ import annotations

import pytest

from ews_mcp.sealing import SealError, new_key_pair, open_sealed, seal, unwrap_key, wrap_key


def test_seal_and_wrap_round_trip() -> None:
    priv, pub = new_key_pair()
    blob = seal(pub, "s3cret", context="g|a@x")
    assert b"s3cret" not in blob
    wrapped = wrap_key(priv, "token-1", context="g")
    assert priv not in wrapped
    assert open_sealed(unwrap_key(wrapped, "token-1", context="g"), blob, context="g|a@x") == "s3cret"


def test_wrong_token_context_or_key_fails() -> None:
    priv, pub = new_key_pair()
    other_priv, _ = new_key_pair()
    blob = seal(pub, "s3cret", context="g|a@x")
    wrapped = wrap_key(priv, "token-1", context="g")
    with pytest.raises(SealError):
        unwrap_key(wrapped, "token-2", context="g")
    with pytest.raises(SealError):
        unwrap_key(wrapped, "token-1", context="other-grant")
    with pytest.raises(SealError):
        open_sealed(other_priv, blob, context="g|a@x")
    with pytest.raises(SealError):
        open_sealed(priv, blob, context="g|b@x")  # a sealed password cannot be moved to another mailbox
