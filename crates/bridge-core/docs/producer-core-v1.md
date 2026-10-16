# Producer core boundary v1

Contract: `bridge-producer-core-v1`, revision 3. Provider: the core. Consumers: the
wire/client boundary (`bridge-protocol`, `bridge-sdk`) and the native registration
coordinator in `bridge-adapters`. Status: implemented. Native qualification is recorded
in the [qualification matrix](../../../docs/qualification.md); this document claims no
installed service and no consumer migration.

## Ownership and dependencies

Core owns shared producer authorization, durable registration/return routes,
opaque stable identity mappings, event intent/custody, route closure, producer
lifetime retirement and the pre-invoking fence. It consumes wire DTOs from
`bridge-producer-wire-v1` and genuinely verified native registration facts from
`bridge-producer-native-v1`.

Only `crates/bridge-core` source, tests and documentation are owned here. Consumer
projects, native proof algorithms, protocol/SDK algorithms, workspace/dependency
changes, installed state and releases are excluded. No product name, tool-name
parser, operation type or payload interpretation belongs in this boundary.

## Shared per-boot authority

`GrantConfig.producer_v1: Option<ProducerPolicy>` defaults to `None`; v1 mutation
admission is opt-in and legacy grant behavior stays unchanged. ProducerPolicy
contains only generic registration/reply-policy/lifetime/audience permissions.
Existing recipient, kind, mode and policy allowlists remain the publication
constraints. Kind is bounded to the existing canonical core limit of 64 bytes;
other opaque request/operation/event keys are at most 256 bytes.

One immutable `Arc<ProducerAuthorizer>` is constructed from the validated boot
configuration and installed in both service state and Storage. Native adapter
Custody access uses that same instance. Neither raw credentials nor credential
hashes or independent policy copies are persisted. Authentication is
constant-time using the existing core comparison semantics. Credentials never
appear in a producer-controlled identity, Debug output, receipt, hash or log.

Rust helper methods (owned by core):

- `ProducerAuthorizer::new(grants: &[GrantConfig]) -> Result<Self, ApiError>`
- `ProducerAuthorizer::authenticate(&self, credential: &str)
  -> Result<&ProducerPolicyGrant, ApiError>`
- `Storage::install_producer_authorizer(&mut self,
  authorizer: Arc<ProducerAuthorizer>) -> Result<(), ApiError>`
- `Storage::producer_authorizer(&self)
  -> Result<Arc<ProducerAuthorizer>, ApiError>`

The grant reference is a trusted in-process policy view, never wire authority or
fresh native authority. Installing the same Arc is an idempotent no-op; replacing
an already installed instance refuses. A newly opened store can install a new
boot policy. Token rotation preserves configured producer identity. Invalid,
revoked or operator credentials cannot read producer records.

UniversalLimits is a separate bounded core configuration: active routes and
retained route/request/evidence/scope identities have hard capacities. Limits
are not a producer job timeout. Exhaustion refuses without silent eviction;
namespace/operator retirement is separate policy outside this implementation.

## Trusted native input

Core-owned `VerifiedRegistration` has these semantic fields:

| Field | Meaning |
| --- | --- |
| caller_address | Actual verified NativeAddress, including host/harness/store namespace/session |
| native_actor_id | Exact native actor, including a child actor when the host shares a session |
| actor_role | `bridge_protocol::ActorRole::Root` or `Child`, never inferred from destination equality |
| destination | Adapter-derived frozen NativeAddress under explicit self/shared_session policy |
| observed_at_ms | Genuine native observation time, Unix milliseconds |
| endpoint_epoch | Verified endpoint/incarnation fence, not logical identity |
| harness_pid, harness_start_time | Actual native process incarnation, not logical identity |
| evidence_use_key | One boot-qualified globally unique native observation key, shared by direct/sealed derivatives |
| evidence_expires_at_ms | Finite native claim validity, checked again at commit time |

This type is an internal trusted-Rust boundary, not a deserializable producer
claim. The native registration coordinator owns qualification, reserved exclusive proof use and construction.
Core validates domains, timestamp/expiry consistency, route policy and global
claim uniqueness; it does not authenticate native hooks or invent caller facts.

Logical caller mapping is producer + canonical caller address + native actor +
root/child role. Destination mapping is producer + canonical frozen destination.
Neither mapping contains native call id, PID/start, endpoint epoch or boot.
Separate durable mappings issue random opaque references from operating-system
randomness using the standard library. Same destination never merges actors.

## Registration storage API and lock order

Typed methods use `bridge_protocol::RegisterCallParams` and its stable public
`RegistrationReceipt`; core does not return fresh assertions:

- `Storage::registration_replay(&self, credential: &str, request_id: &str,
  params: &RegisterCallParams) -> Result<Option<RegistrationReceipt>, ApiError>`
- `Storage::register_call(&mut self, credential: &str, request_id: &str,
  params: &RegisterCallParams, verified: Option<&VerifiedRegistration>,
  clock: &dyn Fn() -> u64) -> Result<RegistrationReceipt, ApiError>`
- `Storage::registration_evidence_committed(&self, credential: &str,
  request_id: &str, use_key: &str)
  -> Result<RegistrationReconciliation, ApiError>`

`RegistrationReconciliation` contains optional historical receipt and claim
state `NotVisible`, `CommittedToRequest` or `CommittedElsewhere`. The latter
reveals no other producer/caller record on the public wire: the adapter emits a
non-disclosing duplicate-evidence conflict. `NotVisible` is not proof that no
in-flight commit can exist. A stored receipt and matching claim are one atomic
fact; inconsistent durable rows are an integrity failure, never invented data.

Order: authenticate and recover an exact committed request under Custody first;
reserve exclusive fresh Registry evidence only for new registration; release
Registry lock; commit under Custody; release Custody; finalize native claim.
Registry and Storage locks never overlap or cover socket I/O. Existing native
attestation/redemption respects the reservation. Unknown commit keeps the claim
pinned until same-request/use reconciliation; only proven noncommit releases it.

The clock is sampled inside the acquired immediate transaction. Production
passes `current_unix_millis`; tests pass a controlled clock. A stale arrival-time
value cannot extend a claim through lock contention. All current-policy,
capacity, expiry and unique-use checks precede the same durable commit.

Registration request identity is `(producer, request_id)`, operation ownership
is `(producer, operation_key)`, evidence use is globally unique `use_key`.
Request and operation-binding fingerprints are distinct. Core and native coordinator
reuse protocol `registration_request_fingerprint(&RegisterCallParams)` with domain
separator `bridge-producer-registration-v1\n`; no duplicate semantic hashing is
implemented in adapters. Request hashing omits
credentials, evidence bytes and transport fields, normalizes sets and retains an
inherit-policy sentinel for omitted kinds; first effective constraints are
stored separately. Operation hashing freezes logical caller, destination,
reply policy and route constraints and excludes transient assertion request.

Exact committed request replay returns original historical receipt before new
proof spending. Supplying an available nonconsuming verified origin may reject
a different caller/destination but never grants freshness, extends validity or
mints an assertion. Missing/stale/consumed supplied evidence does not transform
a durable receipt into authority. New request id for an existing operation
requires genuine fresh evidence; same immutable binding reuses the route,
changed binding conflicts. Closed/expired routes never reopen.

The native coordinator may separately issue a short-lived audience-bound assertion after durable
registration. That assertion, its consumption and freshness remain native
provider responsibilities. Postcommit assertion failure cannot report the
registration as `not_committed`.

## Publication, status and lifecycle APIs

Typed methods:

- `Storage::publish_v1(&mut self, credential: &str, params: &PublishParams,
  clock: &dyn Fn() -> u64) -> Result<PublishResult, ApiError>`
- `Storage::status_v1(&self, credential: &str, selector: &StatusSelector,
  now_ms: u64) -> Result<StatusResult, ApiError>`
- `Storage::close_route(&mut self, credential: &str, request_id: &str,
  params: &CloseRouteParams, clock: &dyn Fn() -> u64)
  -> Result<CloseResult, ApiError>`
- `Storage::retire_delivery_scope(&mut self, credential: &str,
  request_id: &str, params: &RetireDeliveryScopeParams,
  clock: &dyn Fn() -> u64) -> Result<RetireResult, ApiError>`

V1 ingress uses these methods; legacy Requests/Responses remain separate.
Capability reads disclose only the authenticated producer's effective policy,
limits and supported operation/evidence/mode variants. They spend no evidence.
The native adapter currently advertises an empty `native_contracts` list: it
discloses no host build or build digest, and harness policies are operator
configuration and do not constitute live native evidence. Unsupported optional
capabilities refuse explicitly.

Publication first authenticates and compares an existing immutable v1 intent;
exact accepted retry returns original custody even after route closure/expiry
or policy tightening. New custody checks current grant, frozen route constraints,
route/lifetime openness and canonical renderability in the same transaction.
Normalized intent includes tagged route/address destination, event data,
absolute event expiry and optional producer-owned delivery_scope_key; it omits
outer request id/credential/native evidence. Core reuses protocol `publication_intent_fingerprint(&PublishParams)`, SHA-256
over canonical normalized fields with domain separator
`bridge-producer-intent-v1\n`; the SDK independently verifies the same hash. No legacy event id can
be adopted as v1 merely because the resolved envelope matches.

Reuse existing canonical envelope insertion through a transaction-local helper:
v1 intent and old canonical envelope commit together. No historical event bytes,
canonical hashes or legacy dedup meaning change. EventReceipt freezes producer,
event id, intent/envelope hashes, acceptance time/sequence and destination facts;
PublishResult adds replayed. Custody is not native acceptance or processing.

Status selects exactly one owned registration request, route or event. An absent
record is no visible commit at that observation, never cancellation. Registration
status is historical. RouteStatus separates immutable original receipt from
current open/closed/expired state. EventStatus separates custody state from
finite delivery state, optional attempt/effective mode, attempt count/sequence,
observed evidence-tier set, opaque incident reference and bounded generic reasons.
No payload, assertion, secret or product job state appears in status.

Close commits its request semantics/receipt with route closure and fences only
new custody. Exact accepted event retry still works; accepted events keep their
frozen destination and ordinary delivery/expiry/recovery. Expired routes stay
expired; close never extends/reopens, recalls or authorizes replay of effects.

## Producer delivery lifetime

A delivery_scope_key is opaque, producer-owned and never reused; it is distinct
from issuer-generated identity scopes, routes and native invocation keys. First
eligible publication opens it; retiring an unknown key first creates a permanent
closed tombstone. Retirement action is immutable: preserve-to-retire_unhanded
change conflicts. Exact request target/action changes conflict.

Preserve closes new custody only. Retire_unhanded also durably fences reservation
and every new invoking transition, including already reserved manifests. The
invoking commit is the linearization point before native bytes can leave. If
retirement committed first, a reservation is settled/fenced and cannot newly
invoke. If invoking committed first, the possible effect is preserved even if
native writing has not yet been observed. Inject and message enforce the same
fence; expiry, reservation release and restart never remove it.

Retirement safely disposes only proved unhanded/reserved members with no
unresolved possible-effect history. Operator-authorized retries of earlier
unknown effects are not reclassified as never sent. Invoking, held, written,
unknown and accepted effects and their late evidence remain retained; retirement
is neither recall nor duplicate-risk retry authority. `retire_unhanded` permanently
rejects manual retry of its members. A late known-unsent outcome closes a retired
member only when the shared possible-effect check finds no historical risk; otherwise
it keeps the review and a visible incident. A retired orphan row from an older build is
excluded from selection and work listings and shows a scope-fence diagnostic. Source/product-generation
validity remains with the producer.

Coalescing, latest watermarks/lineage and batching include the delivery scope
for scoped v1 events; no manifest mixes sibling lifetimes. Unscoped legacy
behavior remains exact. Route closure and lifetime retirement are distinct.

RetireResult contains immutable receipt plus replayed. Receipt freezes producer,
request/scope/action/time and four disjoint snapshot counts. Precedence: any
possible/uncertain historical effect -> preserved_possible_effect; safe terminal
-> already_terminal; safe live unhanded/reserved -> disposed for retire_unhanded
or preserved_unhanded for preserve. No unbounded identities are returned. Exact
per-event status provides identity/disposition. Later native evidence changes
status, never the original retirement snapshot or retry receipt.

## Schema, faults and compatibility

Schema 5 to 6 is an additive transactional migration. Tables cover
routes, random actor/destination mappings, registration-request fingerprints,
global evidence uses, v1 publication intents, close requests, producer lifetime
tombstones and retire receipts. Events gain a separate lifetime column; scoped
watermark keys gain lifetime. Legacy blank lifetime rows retain their meaning: a lifetime event uses its full nine-field
scoped key (`scoped_watermarks`), an unscoped eight-field legacy key uses `watermarks`,
and a malformed or mismatched lifetime refuses.
Migrations preserve accepted payload bytes/hash/order/ids and unknown attempts.
A newer/unknown schema refuses before Bridge makes any schema or journal-mode change and
without a close-time WAL checkpoint; no destructive rollback is invented. SQLite's own
recovery of an interrupted rollback journal may run first and restore the last committed
content, which can write the main file or remove that journal; ordinary WAL reads or
recovery may rewrite advisory `-shm` WAL-index metadata, while the main and WAL bytes of a
refused WAL database are preserved. Rollback validation or any supported migration holds
an exclusive lock through enabling WAL, then reopens for normal sharing; an existing WAL
database validates normally.

Before COMMIT, known validation/auth/capacity/fence failures have not_committed
and leave no durable effect. Failure/ack loss at COMMIT is unknown with stable
reconciliation identity; exact retry recovers original committed receipt. Never
infer not_committed solely from a transport failure or absent status. Claim,
route and event id non-reuse survives restart and receipt/tombstone retention.

Required controls: atomic request/route/global-claim registration and replay;
inherit/default normalization; actor/root/child conflicts; producer privacy;
intent/legacy collision; custody/close/retire races; retire before first publish;
reservation versus invoking fences; scope-isolated latest/batch; unknown effects
and late evidence; crash/ack windows; schema-five migration; legacy wire/hash
compatibility; hard capacity/redaction; correct-pass, meaningful mutant-fail and
restored-pass on the source under test. Owned core regression and generic fixture controls
are part of the test suite; genuine native composition is a separate gate.
