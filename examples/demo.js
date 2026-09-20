'use strict';
// AuthraGen v2 end-to-end: self-custody, intent binding, approvals, negatives, revocation.
const fs = require('node:fs');
const path = require('node:path');
const { AuthraGen } = require('../sdk-js/authragen');

const BASE = process.env.AUTHRA_URL || 'http://localhost:8787';
const DATA = process.env.AUTHRA_DATA || path.join(__dirname, '..', 'data');

(async () => {
  console.log('== AuthraGen v2 demo ==');
  const bootFile = path.join(DATA, 'bootstrap.token');
  const anon = new AuthraGen({ baseUrl: BASE });

  // first run: bootstrap creates org  ·  repeat runs: reuse cached test org
  let adminSecret = process.env.AUTHRA_ADMIN;
  let org;
  if (fs.existsSync(bootFile) && !adminSecret) {
    const boot = fs.readFileSync(bootFile, 'utf8').trim();
    const withBoot = new AuthraGen({ baseUrl: BASE, bootstrap: boot });
    org = await withBoot.createOrg('acme-' + Date.now().toString(36));
    adminSecret = org.admin_secret;
    console.log('org:', org.id, '| org pubkey:', String(org.org_pubkey).slice(0, 20) + '…');
  } else if (!adminSecret) {
    const testCtx = JSON.parse(fs.readFileSync(path.join(DATA, '.test-ctx.json'), 'utf8'));
    org = { id: testCtx.org_id };
    adminSecret = testCtx.admin;
    console.log('reusing org:', org.id);
  } else {
    org = { id: process.env.AUTHRA_ORG };
    console.log('using org:', org.id);
  }
  const admin = new AuthraGen({ baseUrl: BASE, key: adminSecret });

  // self-custody: keys never leave this process
  const shopK = admin.generateKeypair();
  const shopper = await admin.issuePassport(org.id, 'shopper', { pubkey: shopK.pub });
  console.log('agent:', shopper.id, shopper.did.slice(0, 32) + '…', '| custody:', shopper.custody);
  const resK = admin.generateKeypair();
  const researcher = await admin.issueSubAgent(org.id, shopper.id, 'researcher', { pubkey: resK.pub });
  console.log('sub-agent:', researcher.id, 'parent:', researcher.parent_id);

  const me = new AuthraGen({ baseUrl: BASE }); // no keys: pure agent-sig path

  // 1. read: authorize + execute
  let i = me.intent({ passport_id: shopper.id, org_id: org.id, action: 'data.read', resource: 'catalog:shoes' });
  let d = await me.authorize(i, me.signIntent(i, shopK));
  console.log('1 read:', d.decision, '| risk', d.risk);
  let ex = await me.execute(d.action_token, i);
  console.log('  executed:', ex.ok, '| receipt', ex.receipt.id);

  // 2. delegation (client-signed) + narrowed use + spend
  const tok = await admin.delegate({ org_id: org.id, delegator_id: shopper.id, delegatorPriv: shopK, scope: ['data.read', 'search.*'], resources: ['catalog:*'], constraints: { max_spend_cents: 500, allowed_targets: ['catalog:*'] } });
  console.log('2 token:', tok.id, 'depth', tok.depth, 'targets', tok.constraints.allowed_targets.join(','));
  i = me.intent({ passport_id: shopper.id, org_id: org.id, action: 'search.query', resource: 'catalog:shoes' });
  d = await me.authorize(i, me.signIntent(i, shopK), { token_id: tok.id });
  ex = await me.execute(d.action_token, i);
  console.log('  delegated search:', d.decision, '→ executed', ex.ok);

  // 3. AUTHORITY confusion: researcher tries to narrow SHOPPER's token → must fail
  try {
    await admin.delegate({ org_id: org.id, delegator_id: researcher.id, delegatorPriv: resK, scope: ['data.read'], parent_jti: tok.id });
    console.log('3 authority check: UNEXPECTEDLY ALLOWED (bug)');
  } catch (e) { console.log('3 authority confusion blocked:', e.body?.error || e.message.slice(0, 60)); }

  // 4. allowed_targets: catalog-scoped token cannot touch payments
  i = me.intent({ passport_id: shopper.id, org_id: org.id, action: 'payments.charge', resource: 'stripe:inv:1', amount_cents: 100 });
  d = await me.authorize(i, me.signIntent(i, shopK), { token_id: tok.id });
  console.log('4 target escape:', d.decision, '|', (d.reasons || []).join(',').slice(0, 80));

  // 5. payment → step_up → approver credential → execute; then swap + replay negatives
  const approver = new AuthraGen({ baseUrl: BASE, key: (await admin.mintKey(org.id, 'approver', 'demo')).secret });
  i = me.intent({ passport_id: shopper.id, org_id: org.id, action: 'payments.charge', resource: 'stripe:invoice:42', amount_cents: 499, destination: 'stripe:merchant123' });
  d = await me.authorize(i, me.signIntent(i, shopK));
  console.log('5 payment:', d.decision, '| approval', d.approval_id, '| risk', d.risk);
  const ap = await approver.approve(d.approval_id, true, 'demo-human');
  console.log('  approved, credential:', String(ap.approval_credential).slice(0, 24) + '…');
  ex = await me.execute(ap.action_token, i, { approval: ap.approval_credential });
  console.log('  executed:', ex.ok, '| receipt', ex.receipt.id);
  try { // post-approval swap: same credential, altered amount
    const evil = { ...i, amount_cents: 50000 };
    await me.execute(ap.action_token, evil, { approval: ap.approval_credential });
    console.log('  swap: UNEXPECTEDLY EXECUTED (bug)');
  } catch (e) { console.log('  post-approval swap blocked:', e.body?.error || e.message.slice(0, 60)); }
  try { // replay: same token+intent again
    await me.execute(ap.action_token, i, { approval: ap.approval_credential });
    console.log('  replay: UNEXPECTEDLY EXECUTED (bug)');
  } catch (e) { console.log('  replay blocked:', e.body?.error || e.message.slice(0, 60)); }

  // 6. unauthenticated management is dead
  try { await anon._call('/v1/revoke', 'POST', { type: 'passport', id: shopper.id }); console.log('6 open revoke: STILL OPEN (bug)'); }
  catch (e) { console.log('6 open revoke blocked:', e.status, e.body?.error); }

  // 7. revoke agent → sub-agent fails closed; checkpoint + chain verify
  await admin.revoke('passport', shopper.id, 'demo-cleanup');
  const ri = me.intent({ passport_id: researcher.id, org_id: org.id, action: 'data.read', resource: 'catalog:shoes' });
  const rd = await me.authorize(ri, me.signIntent(ri, resK));
  console.log('7 post-revoke sub-agent:', rd.decision, '|', (rd.reasons || []).join(',').slice(0, 60));
  const cp = await admin.checkpoint();
  console.log('  checkpoint:', cp.count, 'receipts →', String(cp.hash).slice(0, 16) + '…');
  console.log('  audit:', JSON.stringify(await admin.auditVerify(org.id)));
  console.log('== done ==');
  process.exitCode = 0;
})().catch(e => { console.error('DEMO FAILED:', e.body || e.message); process.exitCode = 1; });
