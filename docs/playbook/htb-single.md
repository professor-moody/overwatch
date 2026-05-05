# HTB / Single Host

**Goal:** Pop a single target machine — HTB box, standalone VM, or any one IP.

## Do this

After [Quick Start](../getting-started.md#quick-start-5-minutes), in your `engagement.json` set:

```jsonc
{
  "profile": "single_host",
  "scope": {
    "cidrs": ["10.10.10.5/32"],   // your target IP
    "domains": [],
    "exclusions": []
  }
}
```

Then in Claude:

> **"Run preflight for single_host, scan the target, and start working the frontier."**

That's it. The AI will:

1. Call `run_lab_preflight` to verify nmap/gobuster/etc. are present.
2. Run `nmap` against the target and feed XML to `parse_output`.
3. Pull the frontier and start enumerating discovered services one by one.

## What you'll see in the dashboard

- A single `host` node with `service` nodes for each open port (`RUNS` edges).
- Frontier items prioritized by service — often web enum first, then SMB, then anything else.
- Inference rules will flag obvious wins (anonymous SMB, default creds, known-vulnerable banners).

## When you find a foothold

> **"I have a shell on the target as `www-data`. Open a session and start linpeas."**

The AI opens a PTY/SSH session, runs `linpeas`, parses the output, and starts producing privesc frontier items.

## Tips

- The single-host profile suppresses domain-related warnings (no AD context expected).
- `track_process` long-running scans so they don't block the loop — `check_processes` reaps them.
- Use `get_skill <service-name>` to pull methodology before tackling something unfamiliar.

## See also

- [parse_output vs report_finding](parse-vs-report.md) — which to use for what
- [End-to-End Walkthrough](walkthrough.md) — what the full arc looks like
- [Session Instructions](session-instructions.md) — what the AI does under the hood
