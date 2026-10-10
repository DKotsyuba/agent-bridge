# Agent Bridge

Shared communication service for the Agent MCP family, Codex and Claude Code.

The project is being planned. Product implementation has not started.

Authoritative requirements, decisions, work decomposition and acceptance records
are maintained through Agent Tasks with project alias `agent-bridge`.
The family documentation repository is `../agent-docs/agent-bridge`.

The agreed delivery modes are `inject`, `message` and `auto`:
`auto` selects `inject` for an active recipient and `message` for an inactive one.
An uncertain delivery is retained and reported for manual resolution; it is not
automatically repeated after a possible handoff.
