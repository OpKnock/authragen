"""AuthraGen Python SDK v2 — self-custody by default (needs `cryptography` for key ops;
service-key read/approve paths work without it). Stdlib + cryptography only."""
import json, urllib.request, urllib.error, secrets, time, base64, hashlib

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    _HAS_ED = True
except ImportError:
    _HAS_ED = False

def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def _canonical(o):
    if isinstance(o, dict):
        return "{" + ",".join(json.dumps(k) + ":" + _canonical(o[k]) for k in sorted(o) if k != "signature") + "}"
    if isinstance(o, list):
        return "[" + ",".join(_canonical(x) for x in o) + "]"
    return json.dumps(o, separators=(",", ":"))

class Blocked(Exception):
    def __init__(self, decision):
        super().__init__(f"blocked: {decision.get('reasons')}")
        self.decision = decision

class AuthraGen:
    def __init__(self, base_url="http://localhost:8787", key=None, bootstrap=None):
        self.base = base_url.rstrip("/")
        self.key = key
        self.bootstrap = bootstrap

    def _call(self, path, method="GET", body=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"content-type": "application/json"}
        if self.key: headers["authorization"] = "Bearer " + self.key
        if self.bootstrap: headers["x-bootstrap-token"] = self.bootstrap
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req) as r:
                return json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            try: j = json.loads(e.read().decode() or "{}")
            except Exception: raise
            if "decision" in j: return j
            raise RuntimeError(f"AuthraGen {method} {path}: {e.code} {j}")

    # ---- custody ----
    def generate_keypair(self):
        if not _HAS_ED: raise RuntimeError("pip install cryptography for self-custody keygen")
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        return {
            "pub": _b64u_encode(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
            "d": _b64u_encode(priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())),
        }
    def _priv(self, kp):
        return Ed25519PrivateKey.from_private_bytes(_b64u_decode(kp["d"]))

    # ---- orgs / keys ----
    def create_org(self, name): return self._call("/v1/orgs", "POST", {"name": name})
    def mint_key(self, org_id, role="executor", name=None):
        return self._call(f"/v1/orgs/{org_id}/keys", "POST", {"role": role, "name": name})

    # ---- passports (CSR: YOUR pubkey) ----
    def issue_passport(self, org_id, name, pubkey, **opts):
        return self._call("/v1/passports", "POST", {"org_id": org_id, "name": name, "kind": "agent", "pubkey": pubkey, **opts})
    def issue_subagent(self, org_id, parent_id, name, pubkey, **opts):
        return self._call("/v1/passports", "POST", {"org_id": org_id, "parent_id": parent_id, "name": name, "kind": "subagent", "pubkey": pubkey, **opts})

    def create_agent(self, org_id, name, pubkey, **opts):
        return self.issue_passport(org_id, name, pubkey, **opts)
    def create_blueprint(self, org_id, blueprint):
        return self._call("/v1/blueprints", "POST", {"org_id": org_id, **blueprint})

    # ---- intents ----
    def intent(self, passport_id, org_id, action, resource, amount_cents=0, destination="", tool="", params=None, ttl_ms=60000, aud="authragen"):
        now = int(time.time() * 1000)
        return {"v": 2, "passport_id": passport_id, "org_id": org_id, "action": action, "resource": resource,
                "params": params or {}, "amount_cents": amount_cents, "destination": destination, "tool": tool,
                "nonce": secrets.token_hex(16), "iat": now, "exp": now + ttl_ms, "aud": aud}
    def create_intent(self, *a, **k): return self.intent(*a, **k)
    def intent_hash(self, intent): return hashlib.sha256(_canonical(intent).encode()).hexdigest()
    def sign_intent(self, intent, keypair):
        if not _HAS_ED: raise RuntimeError("pip install cryptography to sign intents")
        return _b64u_encode(self._priv(keypair).sign(_canonical(intent).encode()))
    def authorize(self, intent, intent_sig, token_id=None, kid=None, context=None, dry_run=False):
        return self._call("/v1/authorize", "POST", {"intent": intent, "intent_sig": intent_sig, "token_id": token_id, "kid": kid, "context": context or {}, "dry_run": dry_run})
    def dry_run(self, intent, intent_sig, **k): return self.authorize(intent, intent_sig, dry_run=True, **k)
    def execute(self, action_token, intent, approval=None):
        return self._call("/v1/execute", "POST", {"action_token": action_token, "intent": intent, "approval": approval})
    def guard(self, intent, keypair, token_id=None):
        sig = self.sign_intent(intent, keypair)
        d = self.authorize(intent, sig, token_id)
        if d["decision"] == "allow": return self.execute(d["action_token"], intent)
        if d["decision"] == "step_up": return d
        raise Blocked(d)
    def approve(self, approval_id, approve=True, by_="human"):
        return self._call(f"/v1/approvals/{approval_id}", "POST", {"approve": approve, "by": by_})
    def delegate(self, org_id, delegator_id, delegator_keypair, scope, resources=None, constraints=None, parent_jti=None, kid="k1"):
        if not _HAS_ED: raise RuntimeError("pip install cryptography to sign delegations")
        payload = {"v": 2, "jti": "tkn_" + secrets.token_hex(6), "org_id": org_id, "sub": delegator_id,
                   "parent_jti": parent_jti, "scope": scope, "resources": resources or ["*"],
                   "constraints": constraints or {}, "kid": kid, "iat": int(time.time() * 1000)}
        h = _b64u_encode(json.dumps({"alg": "EdDSA", "typ": "AR1", "v": 1}, separators=(",", ":")).encode())
        p = _b64u_encode(json.dumps(payload, separators=(",", ":")).encode())
        sig = _b64u_encode(self._priv(delegator_keypair).sign(f"{h}.{p}".encode()))
        return self._call("/v1/delegate", "POST", {"org_id": org_id, "delegator_id": delegator_id, "payload": payload, "envelope": f"AR1.{h}.{p}.{sig}"})
    def revoke(self, type_, id_, reason="manual"):
        return self._call("/v1/revoke", "POST", {"type": type_, "id": id_, "reason": reason})

    def verify_offline(self, envelope, org_id):
        return self._call("/v1/verify", "POST", {"envelope": envelope, "org_id": org_id})

    @staticmethod
    def verify_envelope_offline(envelope, org_pub_b64u, expected_aud=None, expected_intent_hash=None):
        out = {"signature_valid": False, "credential_valid": False, "expiry_valid": False, "revocation_freshness": "unknown", "payload": None, "error": None}
        try:
            if not _HAS_ED: raise RuntimeError("pip install cryptography for offline verify")
            parts = envelope.split(".")
            assert len(parts) == 4 and parts[0] == "AR1", "not an AR1 envelope"
            _, h, p, s = parts
            Ed25519PublicKey.from_public_bytes(_b64u_decode(org_pub_b64u)).verify(_b64u_decode(s), f"{h}.{p}".encode())
            out["signature_valid"] = True
            payload = json.loads(_b64u_decode(p).decode())
            out["payload"] = payload
            if not all(payload.get(f) for f in ("jti", "issuer", "aud", "iat", "exp")):
                out["error"] = "token_malformed"; return out
            if payload.get("issuer") != "authragen-gateway":
                out["error"] = "issuer_mismatch"; return out
            if expected_aud and payload.get("aud") not in (expected_aud, "authragen"):
                out["error"] = "audience_mismatch"; return out
            if expected_intent_hash and payload.get("intent_hash") != expected_intent_hash:
                out["error"] = "intent_mismatch"; return out
            out["credential_valid"] = True
            import time as _t
            out["expiry_valid"] = int(_t.time() * 1000) <= payload["exp"]
            if not out["expiry_valid"]: out["error"] = "token_expired"
            return out
        except Exception as e:
            out["error"] = str(e)[:120]; return out
    verify_offline_static = verify_envelope_offline
