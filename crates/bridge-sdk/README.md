# Universal Bridge producer SDK

A synchronous Rust client for the Agent Bridge producer API v1. It depends on
`bridge-protocol`, `serde`, `serde_json` and the locked `socket2` safe Unix connection
API only. It has no core, SQLite, native carrier, MCP framework, producer repository,
business outbox, background sender or connection pool. The legacy `bridge-client` and
operator APIs are separate and unchanged. For the end-to-end onboarding sequence read
[Producer integration](../../docs/producer-integration.md); the wire format is in the
[wire v1 contract](../bridge-protocol/docs/wire-v1.md).

## Add the dependency

The crates are not published to crates.io. Depend on a Git tag (or an exact `rev`) of
this repository, and pin both crates to the same revision:

```toml
[dependencies]
bridge-sdk = { git = "https://github.com/DKotsyuba/agent-bridge", tag = "v0.2.0" }
bridge-protocol = { git = "https://github.com/DKotsyuba/agent-bridge", tag = "v0.2.0" }
```

`bridge-sdk` re-exports `bridge_protocol`, so the second line is only needed when you
use the protocol types directly. Build offline against a vendored or pre-fetched
dependency set if you need reproducibility, and record the tag and the resolved commit.
Workspace-relative path dependencies are development wiring for this repository, not an
integration contract.

## Deployment and identity

Configure a producer credential, permissions and an optional backend audience in
Bridge; onboarding a new project changes configuration only. Use explicit registration
and core Unix endpoints inside service-owned private directories, and never send
credentials, proofs or assertion text through model arguments or logs.

```rust
let client = Client::new(Config::new(
    registration_socket,
    core_socket,
    Secret::new(token),
    Duration::from_secs(5),
)?)?;
```

This validates configuration without any I/O. Credentials may rotate while the configured
producer identity and retained keys stay stable. `capabilities` queries the registration
endpoint and includes authenticated native host facts. Core handles publish, status,
close and retire; the adapter handles registration and optional audience assertions.
Unsupported paths and features are refused explicitly.

## Integration sequence

1. At the actual MCP frontend, preserve the protected `_meta` separately from the
   arguments. `extract_native_evidence(host, &original_meta)` yields an **unverified**
   candidate. Only Bridge's qualified peer, build and hook join can verify it; no working
   directory, environment, model-supplied address or parser result is authority. Direct
   and nested paths are separate.
2. Persist a stable registration request id and an opaque operation incarnation before
   `register_call(id, RegisterCallParams { ... })`. Commit the returned route with your
   normal local admission. Historical receipt recovery grants no new invocation.
3. If detached admission requires an assertion, request the configured audience and an
   opaque forwarded invocation key, then require that an assertion is actually available.
   The backend calls `consume_assertion(id, ConsumeAssertionParams { assertion_key,
   invocation_key })`, which verifies configured audience, peer and linkage. Check original
   expiry, issuer and endpoint fences and current or historical state; operation
   idempotency, sandbox, source and access authority remain the producer's.
4. Persist a stable event id and an immutable publication intent with your domain outcome.
   `publish(exchange_id, PublishParams { destination: Destination::Route { route_key },
   event_id, kind, payload, mode, policy, metadata, expires_at_ms, delivery_scope_key })`
   returns exact validated custody, not native delivery. Once custody is committed, release
   only that local intent and let Bridge own delivery.
5. `status(id, StatusSelector::Event { event_id })` keeps custody, native queue, hook
   emission, context and application evidence separate. No visible record is not
   cancellation. `close_route` fences new events and preserves accepted effects. The
   optional `retire_delivery_scope` fences a producer lifetime; possible native effects
   cannot be recalled or automatically replayed.

## Transport and errors

The configuration is immutable and shareable; each exchange owns one bounded Unix stream.
One absolute deadline covers connect, write, read and an optional single identical
reconnect, and partial traffic never renews it. A retry preserves request and event ids
and bytes. A lost, malformed or mismatched acknowledgement after any possible write is
*unknown*; later failed connects or retry-only preflight rejections do not erase earlier
uncertainty, and only an authoritative same-identity committed result resolves it in this
client. `ClientError` exposes the structured service effect, hint and reconciliation key
without logging response bodies.

## Example

`examples/producer.rs` is a small generic MCP stdin/stdout onboarding probe. Its tool
name, operation, event, kind and payload are runtime inputs, and Bridge and the SDK contain
no producer catalog. It is not a production business outbox. Build it with:

```sh
cargo +1.98.1 build -p bridge-sdk --example producer --offline --locked
```

## Compatibility and tests

API v1, the legacy envelope schema and the database schema are distinct versions.
Unsupported versions refuse before mutation, and optional capabilities must be checked
rather than inferred. The crate's tests (`cargo test -p bridge-sdk`) create short Unix
sockets under `TMPDIR` and prove the DTO and transport boundaries against a local stub;
they do not demonstrate live native qualification or composition with an unknown producer.
Those need real trusted MCP metadata and hooks on an exact host build, see the
[qualification matrix](../../docs/qualification.md).
