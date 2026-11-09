//! Versioned managed-attempt DTOs, separate from the legacy producer API.
//!
//! Transport decoders must also reject duplicate keys recursively; serde's
//! unknown-field checks alone do not provide that guarantee.

use crate::{CallEvidence, Secret};
use serde::{Deserialize, Deserializer, Serialize};

/// Defines a documented strict wire object without altering legacy DTOs.
macro_rules! dto {
    ($name:ident, $doc:literal, { $($field:ident : $ty:ty => $field_doc:literal),* $(,)? }) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            $(#[doc = $field_doc] pub $field: $ty,)*
        }
    };
}

dto!(IncarnationV1, "Full managed kernel process identity.", {
    host_id: String => "Configured host namespace.",
    boot_id: String => "Linux boot UUID.",
    pid_namespace_inode: u64 => "PID namespace inode.",
    uid: u32 => "Effective process UID.",
    pid: u32 => "PID in the observer namespace.",
    start_ticks: u64 => "Kernel process start ticks."
});

/// Only root actors are qualified for the managed v1 contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorRoleV1 {
    /// Original native root actor.
    Root,
}

dto!(ActorV1, "Original native root actor and binding epoch.", {
    address: String => "Canonical native actor address.",
    role: ActorRoleV1 => "Qualified root role.",
    native_id: String => "Native session identifier.",
    epoch: u64 => "Binding epoch at observation."
});

dto!(ObservationV1, "Original protected native hook observation.", {
    incarnation: IncarnationV1 => "Full observed kernel identity.",
    launch_id: String => "Run launch UUID captured directly from the exec environment.",
    actor: ActorV1 => "Observed root actor.",
    native_call_id: String => "Original protected call identifier.",
    tool_name: String => "Exact original native hook tool name.",
    observed_at_ms: u64 => "Bridge-clock observation time in milliseconds.",
    expires_at_ms: u64 => "Original unrenewable Bridge-clock expiry."
});

/// Bridge's assessment; a historical observation cannot authorize new work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidityV1 {
    /// Original observation is fresh and current on Bridge's clock.
    Current,
    /// Original observation is only available for recovery.
    Historical,
}

dto!(AttemptCapabilitiesParamsV1, "Attempt capability discovery request.", {
    version: u16 => "Must be 1."
});
dto!(AttemptCapabilitiesV1, "Authenticated capability advertisement.", {
    version: u16 => "Selected operation version.",
    store_id: String => "Durable Bridge store UUID to pin out of band.",
    capabilities: Vec<String> => "Supported managed capability names.",
    issuer_epoch: String => "Current Bridge issuer epoch."
});
dto!(PrepareNativeContextParamsV1, "Reserve the original native observation.", {
    version: u16 => "Must be 1.",
    expected_store_id: String => "Pinned Bridge store UUID.",
    expected_issuer_epoch: String => "Issuer epoch obtained from capability discovery.",
    invocation_key: String => "Caller-persisted invocation key.",
    command_name: String => "Exact configured command name.",
    native_proof: CallEvidence => "Original protected native call evidence."
});
dto!(PreparedNativeContextV1, "Original protected context reservation.", {
    version: u16 => "Selected operation version.",
    store_id: String => "Durable Bridge store UUID.",
    bridge_context_ref: Secret => "Protected context reference.",
    invocation_key: String => "Original invocation key.",
    expires_at_ms: u64 => "Original Bridge-clock expiry."
});
dto!(ContextLookupParamsV1, "Read an exact reserved native context.", {
    version: u16 => "Must be 1.",
    expected_store_id: String => "Pinned Bridge store UUID.",
    producer: String => "Original producer identity.",
    bridge_context_ref: Secret => "Protected context reference.",
    invocation_key: String => "Original invocation key."
});
dto!(ContextLookupResultV1, "Original context and Bridge currentness.", {
    version: u16 => "Selected operation version.",
    store_id: String => "Durable Bridge store UUID.",
    bridge_context_ref: Secret => "Original protected context reference.",
    invocation_key: String => "Original invocation key.",
    observation: ObservationV1 => "Original hook observation.",
    issuer_epoch: String => "Original Bridge issuer epoch.",
    validity: ValidityV1 => "Fresh currentness assessed by Bridge."
});
dto!(RegisterLaunchAssertionParamsV1, "Bind a command digest to a reservation.", {
    version: u16 => "Must be 1.",
    expected_store_id: String => "Pinned Bridge store UUID.",
    bridge_context_ref: Secret => "Protected context reference.",
    invocation_key: String => "Original invocation key.",
    command_name: String => "Original exact configured command.",
    security_digest: String => "Normalized command security digest.",
    audience: String => "Configured consumer audience.",
    nonce: String => "Original invocation nonce.",
    native_proof: CallEvidence => "Original protected native call evidence."
});
dto!(RegisteredLaunchAssertionV1, "Registered original assertion.", {
    version: u16 => "Selected operation version.",
    store_id: String => "Durable Bridge store UUID.",
    assertion_key: Secret => "Protected assertion key.",
    invocation_key: String => "Original invocation key.",
    issuer_epoch: String => "Original Bridge issuer epoch.",
    expires_at_ms: u64 => "Original Bridge-clock expiry."
});
dto!(ConsumeLaunchAssertionParamsV1, "Consume one original assertion.", {
    version: u16 => "Must be 1.",
    expected_store_id: String => "Pinned Bridge store UUID.",
    assertion_key: Secret => "Protected assertion key.",
    invocation_key: String => "Original invocation key.",
    security_digest: String => "Original normalized command security digest."
});
dto!(ObservationLookupParamsV1, "Read an exact consumed observation.", {
    version: u16 => "Must be 1.",
    expected_store_id: String => "Pinned Bridge store UUID.",
    producer: String => "Original producer identity.",
    consume_request_id: String => "Original consume envelope request identity.",
    invocation_key: String => "Original invocation key.",
    security_digest: String => "Original normalized command security digest."
});
dto!(ConsumeReceiptV1, "Immutable durable consumed observation.", {
    producer: String => "Original producer identity.",
    consume_request_id: String => "Original consume request identity.",
    invocation_key: String => "Original invocation key.",
    security_digest: String => "Original normalized command security digest.",
    observation: ObservationV1 => "Original protected hook observation.",
    issuer_epoch: String => "Original Bridge issuer epoch.",
    consumed_at_ms: u64 => "First durable consume time."
});
dto!(ConsumeOutcomeV1, "Consumed receipt and freshly assessed Bridge currentness.", {
    version: u16 => "Selected operation version.",
    store_id: String => "Durable Bridge store UUID.",
    receipt: ConsumeReceiptV1 => "Original immutable consume receipt.",
    validity: ValidityV1 => "Bridge currentness at this lookup.",
    aborted: bool => "Whether this association was aborted."
});
dto!(ConsumeAbortParamsV1, "Seal a consume intention against late delivery.", {
    version: u16 => "Must be 1.",
    expected_store_id: String => "Pinned Bridge store UUID.",
    producer: String => "Original producer identity.",
    consume_request_id: String => "Original consume request identity.",
    invocation_key: String => "Original invocation key.",
    security_digest: String => "Original normalized command security digest.",
    audience: String => "Original authenticated consumer audience."
});

/// Decodes a required field which may explicitly contain null.
pub(crate) fn nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

/// Durable consume abort and optional pre-existing receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumeAbortResultV1 {
    /// Selected operation version.
    pub version: u16,
    /// Durable Bridge store UUID.
    pub store_id: String,
    /// Always true for a successful abort.
    pub aborted: bool,
    /// Original receipt if consumption won; the key must be present even if null.
    #[serde(deserialize_with = "nullable")]
    pub receipt: Option<ConsumeReceiptV1>,
}

dto!(RetireAttemptNamespaceParamsV1, "Run-attested old issuer namespace retirement.", {
    version: u16 => "Must be 1.",
    expected_store_id: String => "Pinned Bridge store UUID.",
    producer: String => "Original producer identity.",
    issuer_epoch: String => "Retired original issuer epoch.",
    retirement_key: String => "Caller-persisted retirement identity."
});
dto!(RetireAttemptNamespaceResultV1, "Committed namespace retirement receipt.", {
    version: u16 => "Selected operation version.",
    store_id: String => "Durable Bridge store UUID.",
    producer: String => "Retired producer.",
    issuer_epoch: String => "Retired issuer epoch.",
    retirement_key: String => "Original retirement identity.",
    retired_count: u64 => "Number of records compacted."
});

/// Managed refusal recovery class; it never authorizes a changed identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryV1 {
    /// Recover the original request/association after uncertainty.
    SameKeyLookup,
    /// A fresh invocation may be initiated only under the contract's rules.
    FreshInvocation,
    /// Trusted operator recovery is required.
    Operator,
    /// No automatic recovery applies.
    None,
}

dto!(AttemptErrorV1, "Authenticated versioned managed refusal.", {
    version: u16 => "Selected operation version.",
    store_id: String => "Durable Bridge store UUID.",
    code: String => "Stable bounded refusal code.",
    recovery: RecoveryV1 => "Permitted recovery class."
});
