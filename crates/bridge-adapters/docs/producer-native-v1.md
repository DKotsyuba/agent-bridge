# Native producer ingress v1

Contract ID: `bridge-producer-native-v1`, revision 3. Provider: the native
adapters. Consumers: the protocol/SDK and the core. Status: implemented, with
owned process and SQLite boundary controls. Native host qualification is recorded
separately in the [qualification matrix](../../../docs/qualification.md) and is not
claimed here. Related boundaries are the [wire contract](../../bridge-protocol/docs/wire-v1.md)
(`bridge-producer-wire-v1`) and the [core contract](../../bridge-core/docs/producer-core-v1.md)
(`bridge-producer-core-v1`). This document refines the producer onboarding sequence
in [Producer integration](../../../docs/producer-integration.md) and its detached
invocation transfer.

## Ownership and ingress

The adapter's existing private Unix channel accepts additive versioned producer
requests alongside unchanged hook/legacy attestation requests. Kernel peer PID
and UID are read before request processing. The protocol owns strict bounded
v1 decoding and response types; the adapter owns native verification, ephemeral
claims and audience assertions. The authoritative core owns authentication,
semantic fingerprints, stable scope IDs, routes, receipts and evidence-use
commit/reconciliation. The producer SDK parses native metadata into unverified
candidates only; it contains no registry/core/native dependency.

No producer names, tool-specific business handlers, operation types, argument
parsers or result schemas enter this boundary. The only tool-name classification
is supported native host MCP-call grammar. Payload meaning and local admission,
sandbox/access/source/generation checks remain with the producer.

The registry and custody locks never overlap; neither spans socket I/O. Serving
reuses warmed digest checks of the configured relay and audience
executables and current kernel process facts (harness executables get no digest
check: they are checked for owner, mode and unchanged-since-start process facts); it never hashes executable bytes under an
admission lock.

## Verified origin and claim

New registration requires one exact native MCP invocation or a registry-issued
sealed transfer of it. Direct metadata joins one protected fresh PreToolUse
record belonging to the same verified harness incarnation and binding epoch.
Mixed, ambiguous, foreign, stale, malformed and previously consumed evidence
refuse. Root and child remain distinct even when they share a session address.
An address, operation key, PID, cwd, environment, display name or model-authored
actor field is never evidence.

V1 additionally requires positive supported host MCP-call classification from
the protected hook's bounded tool_name. Known outer functions.exec, non-MCP and
missing/unqualified classifications refuse unsupported_host_path. Classification
recognizes native MCP grammar without a producer/server/tool allowlist. It does
not infer argument integrity or product permission. Legacy attest/seal behavior
is retained. Nested inner-call capability stays unsupported until a genuine
independent protected inner-call correlation has been qualified; an outer proof
cannot register several inner operations, nor even substitute for one inner call.

A reservation freezes the verified caller and its exact source observation into
an exclusive, non-clone claim. The source has one boot-qualified globally unique
evidence_use_key, carried unchanged through direct/sealed derivation. Existing
attest, seal and redemption operations respect the claim fence. Reserved records
and proofs cannot be evicted or reused; exhaustion refuses admission. A claim
is an internal verification fact, never a public bearer route or mutation right.

The core-owned trusted fact has these semantic fields:

| Field | Meaning |
| --- | --- |
| caller_address | Actual qualified canonical native address |
| native_actor_id, actor_role | Actual native root/child actor, independent of destination |
| destination | Frozen self/shared-session return address derived by adapter policy |
| observed_at_ms | Protected source observation, Unix milliseconds |
| endpoint_epoch | Exact native binding epoch at verification |
| harness_pid, harness_start_time | Exact verified kernel process incarnation |
| evidence_use_key | Unique identity of the source use, not a secret or native actor ID |
| evidence_expires_at_ms | Finite absolute source validity bound checked at durable commit |

For self policy a caller must be independently addressable. A shared-address
Claude child requires explicit granted shared_session policy; returning there
never grants root identity, root reads or product mutation permission. A Codex
child's own qualified thread remains its own address. Logical caller scope does
not contain PID, endpoint epoch, native call ID or daemon boot. Destination scope
may be equal for different callers without collapsing their authority.

## Registration coordinator

### OpenCode managed lifecycle

The first-party [lifecycle plugin](../plugins/opencode/index.js) targets OpenCode
2.0.28. Its native prompt and tool hooks observe actual session/call IDs; its
execution event subscription reports activity, terminal execution and deletion.
Session discovery starts `Unknown`; only a genuine terminal execution becomes
`Inactive`. Lost subscriptions and disposal invalidate readiness. Parent facts
come from `session.get`, never display labels or model arguments. The actual
process's absolute `OPENCODE_DB` parent identifies its private store.

OpenCode policies support `message` only; `inject=true` is rejected. A message
uses the existing live launcher's exact direct-parent owner route with protocol
`opencode_input`. Bridge neither guesses an HTTP endpoint nor starts a second
scheduler. Correlated owner admission is native acceptance, not processing;
uncertain outcomes retain their original identity without resend or fallback.

The optional SDK metadata candidate requires both `ai.opencode/sessionID` and
`ai.agent_bridge/toolCallID`. The second field belongs to the trusted first-party
plugin contract: stock OpenCode MCP metadata supplies only the session ID and
is insufficient. Parsing these fields grants no authority. Standalone OpenCode
root MCP registration, child message wake and context injection are unqualified.

Synthetic plugin checks run with `node --test
crates/bridge-adapters/plugins/opencode/index.test.js`; they use no native host.
Native wake qualification remains a separate manual check.

1. Decode/validate v1 and authenticate via core's shared ProducerAuthorizer.
   Core/adapters use one immutable per-boot policy; no second credential or grant
   store lives in the registry.
2. Ask core registration_replay for the authenticated request identity and
   normalized intent before spending or claiming native evidence.
3. An exact committed request recovers its historical receipt even if supplied
   evidence is consumed, expired or lost. It never fabricates current authority
   or refreshes an assertion. If available nonconsuming evidence positively
   proves a different current origin, return conflict. Missing evidence does
   not become either freshness or proof of a different origin.
4. A new request always requires fresh evidence, including a request addressing
   an existing operation. Preflight constraints and optional assertion-capacity
   reservations occur before claiming evidence.
5. Reserve evidence under the registry lock, release that lock, then submit the
   trusted fact to core register_call under custody. Core authenticates again
   and atomically commits route, registration receipt and unique source-use fact.
   Commit-time clock capture occurs inside the custody transaction, not before
   waiting for its lock; an expired proof cannot gain validity while queued.
6. A proven committed result finalizes the claim. A proven not_committed result
   releases it. Unknown commit outcome pins the claim until authoritative
   receipt/use reconciliation; absence of a visible record is not proof that an
   in-flight operation cannot still commit.
7. Produce RegistrationResult from the durable receipt and actual evidence/cache
   state. A route commit remains committed even if requested assertion issuance
   subsequently loses freshness or capacity; assertion may be absent. Only an
   actually active issued assertion permits fresh_assertion_available. Detached
   consumers must require it before their own admission.

Core's agreed internal calls are authenticate, registration_replay,
register_call and registration_evidence_committed. Reconciliation returns
receipt and claim status NotVisible, CommittedToRequest or CommittedElsewhere.
The last is converted to a non-disclosing duplicate-evidence conflict on wire;
NotVisible never authorizes claim release by itself. Method/type spelling is
owned by the related canonical protocol/core definitions, not a parallel schema.

## Detached backend assertion

An optional generic audience configuration maps opaque audience name to an
authenticated producer identity and exact qualified backend executable path/SHA.
It is deployment configuration, never a producer-specific implementation branch.
The adapter verifies kernel UID, loaded executable identity and process incarnation
using existing warmed verification. Credentials authenticate through core first.
A copied model assertion reference without matching authenticated audience/peer
cannot consume or disclose invocation facts.

The bounded ephemeral cache binds producer, audience, invocation_key, original
native call/actor/caller and destination scopes, observation/expiry, issuer boot,
and endpoint/incarnation revocation fence. The trusted frontend supplies one
opaque invocation_key and forwards it with its exact RPC. The backend validates
that linkage locally; Bridge does not parse RPC arguments or claim their integrity.
Expiry is at most 30 seconds from issuance and never extends the source validity.

ConsumeAssertionParams requires the assertion key and the exact forwarded invocation_key.
The service matches invocation_key before spending; a mismatch refuses.
Consumption spends the separate assertion once. Exact same consumer, request
identity and intention recover only the original result/expiry; they never admit
a second job or renew authority. Expired, revoked, wrong-audience/invocation and
new-consumer attempts explicitly refuse. Current/historical consumption outcomes
are distinguished. Historical receipt recovery is not fresh admission authority.
The producer remains responsible for domain idempotency and its local admission.

Bridge restart loses all ephemeral assertions and uncommitted source evidence;
committed route receipts survive but cannot reconstruct fresh assertions. Binding
renewal, retirement or incarnation loss revokes affected unconsumed assertions.
No credentials, raw proof strings or assertion keys enter ordinary Debug/log output.

## Capabilities and acceptance controls

Authenticated capabilities disclose only the producer's permitted boundary.
Native host/build/digest facts are not advertised (the list is empty: no harness
build is predeclared), so a consumer never reads a fake build. Harness-policy
support is distinct from recorded native qualification. Initial
host_observations is unsupported; existing lifecycle hooks/carriers remain intact.

Decisive owned-process controls: direct/sealed reservation exclusivity versus
legacy consumers; exact registration replay before evidence; same operation/new
request needs fresh same-origin; precommit and postcommit restart; commit/ack loss
and global evidence-use conflict; root/child/shared-address isolation; wrong
backend audience/invocation; consumption expiry/retry/issuer boot/endpoint renewal;
outer-wrapper/missing native MCP classification refusal; frame limits/redaction;
and unchanged existing native message/inject behavior. Controls include a meaningful
ownership/fence mutation that fails, restoration and successful control rerun.
Actual native host qualification is separate, observed evidence (see the qualification matrix), not inferred
from a fixture, cache or queue acceptance.

## Consumer integration and owned probe

Registration and consumption use the existing configured adapter channel;
publication/status/close/retirement use the core socket. Native capabilities are
queried on the adapter endpoint and augment the same shared core policy. The
standalone SDK/protocol contain no adapter dependency. NDJSON framing appends
one LF around codec bodies; codec bodies themselves contain no delimiter.

Optional TOML `adapters.audiences` entries have opaque `name`, authenticated
`producer`, and `executable = { path = <absolute backend>, sha256 = <64 hex> }`.
The corresponding core producer policy explicitly grants the audience name.
Do not share a backend credential or executable qualification with an untrusted
frontend; this deployment trust declaration is not product permission. Missing
configuration, wrong peer/executable/producer/invocation or expired/revoked assertion
refuses before a new consume effect. Consumed receipts remain bounded per boot;
exhaustion refuses new assertion capacity rather than dropping their identities.

The Bridge-owned qualification binary supports:
`bridge-fixture universal-mcp <adapter> <core> <token-file> <evidence-file> <config-file>`.
Runtime configuration contains only `tool_name`, `request_id`, `operation_key`,
`event_id`, `kind`, `payload_file`, and `mode`. Choose opaque names independently of
the build under test. The probe preserves actual framework `_meta`, registers using
the public wire, publishes the hidden payload through its route and returns
receipt facts only. It reuses the existing MCP loop, bounded sender and private
credential reader; there is no producer-specific transport or framework.

Owned public controls cover direct/sealed registration, immutable replay and
fresh same-origin reuse, child/shared-address isolation, old attestor exclusion
while an actual commit is paused, deliberately lost response acknowledgment,
nonconsuming foreign-origin refusal, wrapper/missing/mixed host evidence,
unsupported operation/version refusal, original assertion expiry, audience/RPC
linkage, endpoint renewal and issuer boot loss. Existing native message/inject
regression remains covered. Controlled implementation mutations must fail these
public checks and restoration must pass again.
