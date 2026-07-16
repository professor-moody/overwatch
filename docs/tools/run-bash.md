# run_bash

Run an auto-instrumented one-shot shell command.

**Read-only:** No

## Description

Executes `bash -c` through the action lifecycle: validation, approval gate, `action_started`, execution, streaming evidence capture, `action_completed` or `action_failed`, and optional parser ingestion.

Use `run_bash` when shell features are required, such as pipes, redirects, compound commands, or globs. Prefer [`run_tool`](run-tool.md) for simple binary-and-argv invocations.

## Usage Notes

- Provide `technique` and explicit `target_ip`, `target_url`, or `target_node` for target-facing commands.
- `allow_unverified_scope` should be reserved for intentional non-target references.
- Use `parse_with` when the command output has a supported parser and should immediately become graph artifacts.
- Do not request backgrounding or daemonization. Known forms—including unquoted `&`, `nohup`, `setsid`, and common detached/new-session child-process options—are rejected before launch, and descendants left in the managed process group are terminated with an error. Tools that internally self-daemonize are unsupported; launch them through the operator's external terminal and register the PID with [`track_process`](track-process.md) instead.
