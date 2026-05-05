# HTB / Network

**Goal:** Sweep a network range and work whatever you find — HTB ProLab (Dante, Offshore, RastaLabs), internal CIDR, or any range where AD may or may not exist.

## Do this

After [Quick Start](../getting-started.md#quick-start-5-minutes), in your `engagement.json` set:

```jsonc
{
  "profile": "network",       // required — defaults to single_host otherwise
  "scope": {
    "cidrs": ["10.10.110.0/24"],
    "domains": [],             // leave empty — AD will be discovered
    "exclusions": []
  }
}
```

Then in Claude:

> **"Run preflight for network profile, sweep the scope, then work the frontier in priority order."**

The AI will sweep with nmap, ingest results, and start enumerating live hosts. As AD shows up (DCs, Kerberos, LDAP), domain nodes appear automatically.

## When AD is discovered

The AI will flag this. At that point:

> **"AD is in scope now. Run BloodHound collection from one of the hosts and ingest it."**

`ingest_bloodhound` populates users, groups, ACLs, sessions, and local admins. Inference rules fire — Kerberoastable, AS-REP-roastable, GenericAll, ESC1-13, etc.

## Why "network" matters

The `network` profile is the middle ground between `single_host` and `goad_ad`:

- **Multi-host:** expects many targets across the CIDR
- **AD optional:** domain-qualification warnings are suppressed until AD is actually discovered
- **Network discovery frontier items:** track CIDR coverage; `fan_out_estimate` shrinks as hosts are found

If you set `profile: single_host` on a network engagement, you'll get noisy warnings about missing domains. If you set `profile: goad_ad` on a network engagement with no AD, preflight will block on missing domain config. The middle profile fixes both.

## Tips

- Use `track_process` for long sweeps; `check_processes` reaps them.
- Dispatch sub-agents per CIDR with `dispatch_subnet_agents` for parallel sweeps on big ranges.
- The dashboard will show CIDR coverage in real time as the sweep progresses.

## See also

- [GOAD AD Lab](goad-lab.md) — once AD is confirmed, the AD-specific playbook applies
- [Operator Infrastructure](operator-infra.md) — for Responder/relay during the sweep
- [End-to-End Walkthrough](walkthrough.md) — narrated example
