# Producer integration

How a new tool (an MCP server, a CLI, a background worker) becomes a Bridge
producer using API v1 and the `bridge-protocol` and `bridge-sdk` crates. A
producer needs deployment configuration and the library. It does not need a
producer enum, a tool-name parser, a job type, a payload schema, a plugin or a
source branch in Bridge: native adapters understand host evidence, while
operation and event meaning stay with the producer.

References: the [wire contract](../crates/bridge-protocol/docs/wire-v1.md), the
[core contract](../crates/bridge-core/docs/producer-core-v1.md), the [native
ingress contract](../crates/bridge-adapters/docs/producer-native-v1.md) and the
[SDK guide](../crates/bridge-sdk/README.md).

## 1. Onboard a producer (configuration only)

Give the producer one stable authenticated identity and generic permissions in the
private daemon configuration. Replace the credential through your protected
deployment mechanism; never put it in model arguments or ordinary logs.

```toml
[[grant]]
token = "<private-random-credential-at-least-16-bytes>"
publisher = "sample-producer"
recipients = ["*"]
kinds = ["*"]
modes = ["message", "inject"]
policies = ["keep_all"]

[grant.producer_v1]
registration = true
reply_policies = ["self"]
native_scopes = ["*"]
direct_address = false
delivery_scopes = true
assertion_audiences = []
```

Narrow `native_scopes` (exact `host/harness/store` prefixes), recipients, modes and
kinds when you can. These are declarative permissions, not a catalog of
implementations. A grant without `producer_v1` keeps legacy behavior and gains no v1
mutation permission; operator grants are a separate realm. The installation owns the
protected native hooks, the native harness policies and the registration endpoint:
do not copy a caller-binding hook into each producer. Checks on source, access,
admission, generation or business state remain at the producer's own trusted
boundary; Bridge does not replace them. See [Configuration](configuration.md).

## 2. Configure the library

Use explicit absolute registration and core socket paths inside private service
directories, a protected credential and a finite exchange deadline. The library never
discovers identity from the working directory or environment and never inspects host
processes.

```rust
use bridge_sdk::{Client, Config};
use bridge_sdk::bridge_protocol::Secret;
use std::time::Duration;

let client = Client::new(Config::new(
    registration_socket,
    core_socket,
    Secret::new(private_credential),
    Duration::from_secs(5),
)?)?;
let capabilities = client.capabilities(persisted_capability_request_id)?;
```

The SDK depends on `bridge-protocol`, `serde`, `serde_json` and `socket2` only: no
core, SQLite, native carrier, MCP framework or connection pool. Capabilities come
from the registration endpoint and combine authenticated core policy with native path
facts. The native adapter currently advertises an empty build-contract list
(`native_contracts`), so no host build or build digest is disclosed. Registration and
optional assertion consumption use that endpoint; publication, status, close and lifetime
retirement use the core endpoint.
Configured host support is distinct from a qualification receipt, and a feature that is
not advertised is refused explicitly: check capabilities, do not infer them from DTO
availability.

## 3. Register before admitting work

At the actual MCP frontend, preserve the framework-protected `_meta` object separately
from the arguments. `extract_native_evidence(host, &original_meta)` only parses an
**unverified** candidate; the Bridge verified peer, marked harness process, canonical
store and hook join establishes authority. A caller address, native id or route string
supplied by a model cannot substitute for that join. Direct MCP calls are supported on
the host paths the adapter reports as supported; a nested inner call, an outer wrapper
and host observations are not.

Managed OpenCode 2.0.28 uses the first-party component ABI 2 (`native-context`). Its
original permission-checked MCP executor supplies actual ToolContext through a
private parent-authenticated control channel; the persistent stdio proxy adds the
missing native call ID only to the matching session, method and arguments, once.
The SDK still receives protected metadata separately from model arguments and the
normal hook, actor and audience checks remain required. An older lifecycle-only
component cannot supply this contract; deploy matching launcher and component.

1. Persist a stable registration request id and an opaque operation incarnation
   *before* calling `register_call(id, RegisterCallParams { ... })` with
   `operation_key`, `evidence`, `reply_policy` and optional narrowed modes, kinds,
   payload size and expiry.
2. Commit the returned `receipt.route_key` with your normal domain admission; an
   orphan pre-admission route is not a job.
3. The receipt carries an immutable route, `caller_scope` (the actual native actor,
   including root versus child) and `destination_scope` (its permitted return
   address). Equal destinations never imply equal callers. Self-return needs an
   independently addressable actor; a shared-session child needs an explicit granted
   `shared_session` policy, which grants no root role or workspace authority.
4. Hand the stored route reference to the worker through your existing job context;
   never let it guess the orchestrator from the working directory, latest chat or
   parent PID.

## 4. Publish a domain result

Commit an event id and an immutable publication intention together with the domain
outcome, then call `publish(exchange_id, PublishParams { destination:
Destination::Route { route_key }, event_id, kind, payload, mode, policy, metadata,
expires_at_ms, delivery_scope_key })`. Metadata is bounded generic text and `bridge.*`
keys are reserved. A `delivery_scope_key` is a producer-owned lifetime, distinct from
the caller, destination and route.

A successful receipt proves durable Bridge custody for that exact intention. It does
not prove native acceptance, model visibility or domain processing. Once custody is
committed, release only your local publication intention and leave delivery to Bridge;
no native fallback, duplicate sender or second event id repairs an uncertain result.

An authorized producer can instead use `Destination::Address` when `direct_address` is
enabled. No recipient registration and no receiver `bridge_me` call is required, but the
recipient must still have an attested native route: an absent, dead or input-waiting
recipient is a visible hold, never a guessed alternate chat.

`status(id, StatusSelector::Event { event_id })` observes one owned registration, route
or event and keeps custody, native queue, hook emission, context and application
evidence separate. "No visible record" is absence at that observation, not proof that an
in-flight operation cannot still commit.

## 5. Recover and retire

- Keep request ids, operation keys and event ids stable across exact retries. Rotating a
  credential or evidence does not change an immutable intent; a changed intention
  conflicts.
- A lost, malformed or mismatched acknowledgement after a possible write is
  *unknown*. A later retry-only refusal cannot erase that uncertainty, and the SDK keeps
  the original reconciliation key. One absolute deadline covers connect, write, read and
  at most one identical reconnect; partial traffic never renews it.
- Exact committed registration recovery is historical, spends no proof twice, and
  restores the route association after a restart, never a fresh invocation. A new request
  for an existing operation requires fresh same-origin evidence; closed and expired routes
  never reopen. Exact accepted publication recovery stays valid after closure, expiry or
  permission tightening.
- `close_route` fences new custody only; accepted events keep their frozen destination and
  delivery policy. The optional `retire_delivery_scope` closes a producer lifetime:
  `retire_unhanded` also fences reservation and new invoking, including already reserved
  manifests, and permanently rejects manual retry of the retired members. If invoking committed first, the possible effect is retained and cannot be
  recalled; later evidence changes event status, never the immutable retirement counts. A
  scope retired before its first publication stays a permanent tombstone.
- A Bridge restart restores still-live recipient bindings and durable route receipts. It loses
  ephemeral assertions and uncommitted call evidence, which a historical receipt cannot
  reconstruct. Identity and tombstone capacity refuse admission instead of silently
  evicting or reusing a key. There is no implicit job timeout.

## 6. Detached admission (optional)

Ordinary producers do not need assertions. A detached backend that must verify a current
invocation requests a configured `assertion_audience` plus an opaque `invocation_key` at
registration, requires an actually available fresh assertion, and forwards both with its
exact RPC. Bridge verifies the authenticated configured backend executable and audience
before `consume_assertion` and matches `invocation_key` before spending the assertion
once. An exact consumption retry preserves the original context and expiry; a historical or
revoked context never renews admission authority. Domain idempotency, current source,
generation, access and sandbox rules remain the producer's.

## 7. Example, packaging and cutover

`crates/bridge-sdk/examples/producer.rs` is a tiny generic MCP stdin/stdout onboarding
probe whose tool name, operation, event, kind and payload are runtime inputs. It is not
a production outbox. Build it with
`cargo +1.98.1 build -p bridge-sdk --example producer --offline --locked`.

Pin **both** `bridge-protocol` and `bridge-sdk` versions with package checksums and build
the consumer offline against those artifacts and locked third-party dependencies. The
source manifests inherit workspace metadata, so a standalone package must materialize its
own manifests and a versioned protocol dependency. API v1, the legacy envelope schema and
the database schema are distinct versions; unsupported versions refuse before mutation.

When moving an existing sender to Bridge, keep exactly one delivery owner: transfer only
never-attempted or positively known-unsent intentions, keep uncertain or accepted
historical effects without replay, and remove an existing safety mechanism only after
confirming the service's actual capabilities and independently observing native
delivery on your builds.
