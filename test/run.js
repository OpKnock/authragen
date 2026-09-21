      const dr = await me.dryRun(ip, S(ip, aK));
      ok(dr.decision === 'dry_run' && !dr.action_token && !!dr.would, 'dry-run previews without executable credential');
    }

    // --- policy engine: empty arrays match nothing; conflicts; simulate ---
    {
      const pol = await admin._call('/v1/policies', 'POST', { org_id, effect: 'allow', actions: [], resources: [], priority: 999 });
      ok(!!pol.id, 'empty-array policy creatable (matches nothing)');
      const it = I(a.id, 'nomatch.xyz', 'nomatch:1');
      const dd = await me.authorize(it, S(it, aK));
      ok(dd.decision === 'deny', 'empty policy arrays do not grant (fail-closed)');
      const sim = await admin._call('/v1/policies/simulate', 'POST', { org_id, action: 'data.read', resource: 'x:1', context: {} });
      ok(!!sim.would || !!sim.provisional, 'policy simulation endpoint works');
      const conf = await admin._call(`/v1/policies/conflicts?org_id=${org_id}`);
      ok(Array.isArray(conf.conflicts), 'policy conflict detection endpoint works');
      await throwsAsync(() => admin._call('/v1/policies/' + pol.id, 'PUT', { actions: 'data.read' }), /bad_request/, 'policy update rejects malformed action arrays');
      await throwsAsync(() => admin._call('/v1/policies/' + pol.id, 'PUT', { priority: 999999999999999 }), /bad_request/, 'policy update rejects unsafe priority values');
    }

    // --- delegation: authority + attenuation + targets ---
    const t0 = await admin.delegate({ org_id, delegator_id: a.id, delegatorPriv: aK, scope: ['data.read'], resources: ['x:*'], constraints: { max_spend_cents: 500, allowed_targets: ['x:*'], not_after: Date.now() + 7 * 86400000 } });
    ok(t0.depth === 0, 'root delegation depth 0');
    const t1 = await admin.delegate({ org_id, delegator_id: a.id, delegatorPriv: aK, scope: ['data.read'], resources: ['x:*'], constraints: { max_spend_cents: 100 }, parent_jti: t0.id });