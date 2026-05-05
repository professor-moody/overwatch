# register_mock_service

Register an operator-controlled decoy, listener, or relay as a first-class
node in the engagement graph.

**Read-only:** No · **Idempotent:** Yes

## Description

Use this whenever you spin up infrastructure that will *receive* incoming
connections from the target environment — fake LDAP, Responder,
`ntlmrelayx`, socat redirector, reverse-shell catcher, HTTP/SMB capture
endpoint, etc.

Tying the listener to the graph unlocks two things:

1. The built-in **`rule-baited-credential`** inference rule auto-emits a
   `BAITED` edge from the listener to any credential reported with
   `via_mock_service_id` set to this node, so chain analysis and
   retrospectives can attribute the capture.
2. Dashboards and `find_paths` can traverse `OPERATED_BY` /
   `BAITED` / `RELAYED_VIA` edges to show *which* operator
   infrastructure participated in *which* attack.

The tool is **idempotent on `(purpose, bind_host, bind_port, agent_id)`** —
re-calling refreshes `last_seen_at` and `bound_session_id` but does not
duplicate the node, and emits a `mock_service_refreshed` activity event
instead of `mock_service_registered`.

You usually do **not** need to call this directly: `open_session` with
`kind=socket`, `mode=listen`, and `mock_service_purpose` set will call
`registerMockServiceCore` automatically and stamp
`capabilities.serves_mock_service_id` onto the session.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `purpose` | enum | Yes | One of `fake_ldap`, `responder`, `ntlmrelayx`, `redirector`, `reverse_shell_catcher`, `http_capture`, `smb_capture`, `other`. Drives default OPSEC noise. |
| `protocol` | string | Yes | Wire protocol (`ldap`, `smb`, `http`, `https`, `tcp`, `udp`, `raw`, …). |
| `bind_host` | string | Yes | Listener bind address (typically `0.0.0.0`, `127.0.0.1`, or the attacker IP). |
| `bind_port` | int | Yes | TCP/UDP port (1–65535). |
| `opsec_loud` | bool | No | Defaults to `true` for `responder` / `ntlmrelayx` / `fake_ldap` / `smb_capture`, `false` otherwise. |
| `notes` | string | No | Free-form analyst notes. |
| `bound_session_id` | string | No | Session ID of the long-lived process running the listener. |
| `bound_process_id` | int | No | OS pid of the listener process. |
| `target_node` | string | No | Host node id for the `RUNS_ON` edge (omit if the attacker host is not in the graph). |
| `agent_id` | string | No | Operator agent id; used for `OPERATED_BY` attribution and dedupe key. |
| `action_id` | string | No | Standard action linkage. |
| `frontier_item_id` | string | No | Standard frontier linkage. |

## Returns

```json
{
  "registered": true,
  "new": true,
  "mock_service_id": "mock-svc-responder-3a1f...",
  "event_id": "evt-...",
  "operator_edge": { "added": false },
  "runs_on_edge": { "added": true, "edge_id": "..." }
}
```

| Field | Description |
|-------|-------------|
| `new` | `true` on first registration; `false` on idempotent refresh. |
| `mock_service_id` | Stable id derived from `(purpose, bind_host, bind_port, agent_id)`. |
| `operator_edge` | Whether an `OPERATED_BY` edge was added (only when `agent_id` matches an existing `user` node). |
| `runs_on_edge` | Whether a `RUNS_ON` edge was added (only when `target_node` resolves to a `host`). |

## Graph Schema

The tool produces / interacts with these nodes and edges:

| Element | Direction | Notes |
|---------|-----------|-------|
| `mock_service` node | — | Stores `mock_purpose`, `bind_host`, `bind_port`, `protocol`, `opsec_loud`, `started_at`, `stopped_at`, `bound_session_id`, `bound_process_id`. |
| `OPERATED_BY` | `mock_service → user` | Conditional; needs an existing user node. |
| `RUNS_ON` | `mock_service → host` | Conditional; needs `target_node` to resolve to a host. |
| `BAITED` | `mock_service → credential` | Emitted by the inference engine when a credential is reported with `via_mock_service_id`. |
| `RELAYED_VIA` | `credential → mock_service` | Operator can add manually via `report_finding` for relay chains. |

## Workflow

```text
1. open_session kind=socket mode=listen port=445 \
     mock_service_purpose=responder mock_service_protocol=smb
   → server auto-calls register_mock_service
   → session.capabilities.serves_mock_service_id is stamped

2. (target machine fires a poisoned NetBIOS query and authenticates)

3. report_finding nodes=[{
     type: 'credential',
     cred_user: 'svc_sql', cred_domain: 'CORP',
     cred_type: 'ntlmv2_challenge',
     via_mock_service_id: '<id from step 1>'
   }]
   → inference engine emits BAITED edge from listener → credential
   → frontier scoring picks up the new credential as a fresh test target

4. close_session
   → server stamps stopped_at on the mock_service node
   → dashboard renders the listener as inactive
```

## Usage Notes

- Prefer the `open_session` integration for the common case (one
  listener bound to one persistent session). Call this tool directly
  only when the listener runs out-of-band (e.g. inside a container
  whose pid you don't expose).
- The **owner** is part of the dedupe key on purpose: two operators
  running independent Responders on the same box do *not* collapse to
  one node.
- `opsec_loud=true` mock services are the right place to surface
  warnings in retrospectives ("captured 3 hashes via Responder while
  OPSEC profile = stealth").
- The `RELAYED_VIA` edge is intentionally not auto-inferred — emit it
  by hand when you observe an actual relay (e.g. credential captured on
  Responder then replayed via `ntlmrelayx`).
