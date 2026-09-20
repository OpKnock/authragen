"""AuthraGen Python v2 demo — self-custody, intent binding, approval credential."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sdk_python.authragen import AuthraGen, Blocked

BASE = os.environ.get("AUTHRA_URL", "http://localhost:8787")
DATA = os.environ.get("AUTHRA_DATA", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data"))

anon = AuthraGen(BASE)
boot_path = os.path.join(DATA, "bootstrap.token")
ctx_path = os.path.join(DATA, ".test-ctx.json")
if os.path.exists(boot_path):
    boot = open(boot_path).read().strip()
    org = AuthraGen(BASE, bootstrap=boot).create_org("py-acme")
    admin_secret = org["admin_secret"]
elif os.path.exists(ctx_path):
    import json as _json
    t = _json.load(open(ctx_path))
    org = {"id": t["org_id"]}
    admin_secret = t["admin"]
    print("reusing org:", org["id"])
else:
    org = {"id": os.environ["AUTHRA_ORG"]}
    admin_secret = os.environ["AUTHRA_ADMIN"]
print("org:", org["id"])
admin = AuthraGen(BASE, key=admin_secret)

shopK = admin.generate_keypair()
shopper = admin.issue_passport(org["id"], "py-shopper", shopK["pub"])
print("agent:", shopper["id"], "| custody:", shopper["custody"])

me = AuthraGen(BASE)
i = me.intent(shopper["id"], org["id"], "data.read", "catalog:hats")
d = me.authorize(i, me.sign_intent(i, shopK))
ex = me.execute(d["action_token"], i)
print("read:", d["decision"], "-> executed", ex["ok"], ex["receipt"]["id"])

appr_key = admin.mint_key(org["id"], "approver", "py")["secret"]
approver = AuthraGen(BASE, key=appr_key)
i = me.intent(shopper["id"], org["id"], "payments.charge", "stripe:inv:7", amount_cents=1200)
d = me.authorize(i, me.sign_intent(i, shopK))
print("payment:", d["decision"], "| risk", d["risk"])
ap = approver.approve(d["approval_id"], True, "py-human")
ex = me.execute(ap["action_token"], i, ap["approval_credential"])
print("approved+executed:", ex["ok"], ex["receipt"]["id"])
try:
    me.execute(ap["action_token"], i, ap["approval_credential"])
    print("replay: UNEXPECTEDLY EXECUTED")
except RuntimeError as e:
    print("replay blocked:", str(e)[:70])
print("== python demo done ==")
