# run_tool

Run an auto-instrumented one-shot argv-form command.

**Read-only:** No

## Description

Executes a binary with an argv array through the same lifecycle as [`run_bash`](run-bash.md): validation, approval gate, action logging, streaming evidence capture, and optional parser ingestion.

Use `run_tool` when no shell features are needed. It avoids shell parsing and is the preferred path for scanner and CLI invocations with explicit arguments.

## Usage Notes

- Provide the executable and arguments separately.
- Provide `technique` and explicit target metadata for target-facing commands.
- Use `parse_with` for supported raw output formats.
