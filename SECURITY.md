# Security policy

## Reporting a vulnerability

Report privately through GitHub:
[Report a vulnerability](https://github.com/DKotsyuba/agent-bridge/security/advisories/new).
Please do not open a public issue or pull request for a security problem, and do
not include real tokens, session identifiers or message payloads in a report;
a minimal synthetic reproduction is enough.

Reports are handled on a best-effort basis by the maintainer. Include the
version (`bridge version` or the commit), the platform, what you expected, what
happened, and how an attacker would reach it.

## Supported versions

Only the latest commit on the default branch is supported. Bridge is
pre-1.0 software distributed as source.

## Trust boundary

Bridge is a same-user local service. Read the trust model in the [adapter
guide](crates/bridge-adapters/README.md) and the [architecture
notes](docs/architecture.md) before judging a finding. In particular:

- A caller is authenticated by a grant token plus socket access; tokens are
  at least 16 bytes, compared in constant time, never printed, and kept in
  files readable only by their owner.
- Sockets live in directories that must be mode `0700`. Code running as the same
  user inside a harness's own tool sandbox can replay a hook client, so deny the
  channel directory to that sandbox. Hostile code running as the same user is
  outside the claimed isolation.
- Native identity comes from kernel peer credentials, process ancestry, the
  harness executable's SHA-256, and the harness's own hook and MCP metadata.
  Labels, PIDs alone, working directories and model-authored fields are never
  accepted as proof.
- Message bodies are rendered as external data with an explicit no-authority
  statement. Bridge never answers a permission request on a recipient's behalf.
- The optional Telegram notifier is outbound-only, to one fixed chat, and
  reads its token from a protected file.

Reports about a weakened boundary above, credential or payload disclosure,
unauthorized publication or recovery decisions, a repeated uncertain delivery,
or corruption of custody are in scope. Findings that require an attacker to
already run arbitrary code as the same user outside a sandboxed harness are
generally out of scope.
