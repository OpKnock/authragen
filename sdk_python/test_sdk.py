import hashlib

from authragen import AuthraGen, Blocked, _canonical


def test_canonical_is_deterministic_and_sorted():
    assert _canonical({"b": 2, "a": 1}) == '{"a":1,"b":2}'
    assert _canonical({"signature": "drop", "a": 1}) == '{"a":1}'


def test_intent_shape_and_hash():
    sdk = AuthraGen(base_url="http://example.invalid")
    intent = sdk.intent("agt_demo", "org_demo", "data.read", "catalog:item")
    assert intent["v"] == 2
    assert len(intent["nonce"]) == 32
    assert sdk.intent_hash(intent) == hashlib.sha256(_canonical(intent).encode()).hexdigest()


def test_guarded_block_type():
    err = Blocked({"decision": "deny", "reasons": ["policy"]})
    assert "policy" in str(err)
