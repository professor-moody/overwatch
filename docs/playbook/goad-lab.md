# GOAD AD Lab

**Goal:** Run a full Active Directory engagement against GOAD (Game of Active Directory), Proxmox AD, or any multi-host AD lab.

## Do this

After [Quick Start](../getting-started.md#quick-start-5-minutes), in your `engagement.json` set:

```jsonc
{
  "profile": "goad_ad",
  "scope": {
    "cidrs": ["192.168.56.0/24"],                              // your lab network
    "domains": ["sevenkingdoms.local", "north.sevenkingdoms.local"],  // your AD domains
    "exclusions": []
  }
}
```

Then in Claude:

> **"Run preflight for goad_ad. Once it passes, scan the lab, ingest BloodHound, and start working the frontier."**

The AI will:

1. Verify nmap, nxc, impacket, bloodhound-python, certipy are installed.
2. Sweep the lab with nmap.
3. Ingest BloodHound (it will ask you for the path or run collection itself if creds are available).
4. Watch inference rules fire — Kerberoastable, AS-REP-roastable, GenericAll, ESC1-13, DCSync paths, the works.

## You'll watch the graph explode

Once BloodHound lands, expect:

- Hundreds of `user`, `group`, `computer` nodes.
- ACL edges (`GENERIC_ALL`, `WRITEABLE_BY`, `FORCE_CHANGE_PASSWORD`, `ADD_MEMBER`).
- ADCS edges if certipy ran (`ESC1` through `ESC13`).
- Trust edges between domains (`TRUSTS`).

The dashboard's path overlays become useful here — Shift+click any owned credential and a target group like Domain Admins to see the shortest attack chain.

## Common AD workflows

> **"Kerberoast every SPN in the domain and feed the hashes to hashcat with the rockyou wordlist."**
> The AI runs `GetUserSPNs.py`, parses output, runs hashcat, parses cracked hashes back into the graph as `cred_value` properties on the existing user nodes.

> **"Find every path from any owned credential to Domain Admin and pick the shortest one."**
> Triggers `find_paths` and the AI proposes the next concrete action (e.g., "abuse `GenericAll` on `dc01$` via shadow credentials").

> **"Set up Responder on my interface and watch for hashes during the lunch window."**
> See [Operator Infrastructure](operator-infra.md). The captured hashes will be tied via `BAITED` edges back to your listener.

## Tips

- **Run BloodHound early.** Inference rules need the structural data. Without it, the AI is guessing.
- **Sub-agents are your friend.** AD engagements have lots of independent enum tasks — dispatch them in parallel with `dispatch_agents` or `dispatch_campaign_agents`.
- **`run_graph_health` after big ingests.** Catches dangling edges or property issues before they propagate.
- **Watch for ESC1-13 frontier items.** ADCS misconfigs are often the fastest path.

## See also

- [Operator Infrastructure](operator-infra.md) — Responder/relay workflows
- [End-to-End Walkthrough](walkthrough.md) — narrated GOAD-style engagement
- [Concepts — Credential Lifecycle](../concepts.md#credential-lifecycle) — how creds flow through the graph
