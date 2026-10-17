//! Shared immutable per-boot producer authorization and universal admission caps.
//! Credentials remain only in this memory object; both ingress paths use the
//! same Arc installed in Storage, never an independent native grant database.

use crate::service::GrantConfig;
use bridge_protocol::{ApiError, ErrorClass, RetryHint};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Opt-in generic v1 permissions; no operation, job or product semantics.
/// Missing policy disables v1 mutations and host observations; native scopes must be explicitly
/// declared and shared-session return requires an explicit reply permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProducerPolicy {
    /// Whether fresh native call registration is admitted.
    pub registration: bool,
    /// Permitted native return policies; default only `self`.
    pub reply_policies: Vec<String>,
    /// Exact canonical host/harness/store prefixes, or explicit `*`.
    pub native_scopes: Vec<String>,
    /// Whether v1 direct-address publication is admitted.
    pub direct_address: bool,
    /// Whether producer lifetime creation/retirement is admitted.
    pub delivery_scopes: bool,
    /// Enables exact recipient observation/resolution on the adapter endpoint;
    /// recipient and native scope allowlists still apply before any lookup.
    pub host_observations: bool,
    /// Literal configured backend audience names allowed for assertion issue.
    pub assertion_audiences: Vec<String>,
}
impl Default for ProducerPolicy {
    /// Denies mutation and host-observation features unless explicitly enabled.
    fn default() -> Self {
        Self {
            registration: false,
            reply_policies: vec!["self".into()],
            native_scopes: Vec::new(),
            direct_address: false,
            delivery_scopes: false,
            host_observations: false,
            assertion_audiences: Vec::new(),
        }
    }
}
impl ProducerPolicy {
    /// Validates bounded unique declarations, native store prefixes and policy
    /// names; malformed deployment configuration never becomes authorization.
    pub fn validate(&self) -> Result<(), ApiError> {
        for values in [
            &self.reply_policies,
            &self.native_scopes,
            &self.assertion_audiences,
        ] {
            if values.len() > 64
                || values.iter().any(|v| !opaque(v))
                || values
                    .iter()
                    .enumerate()
                    .any(|(i, v)| values[..i].contains(v))
            {
                return Err(failure(ErrorClass::Invalid, "invalid_producer_policy"));
            }
        }
        if self
            .reply_policies
            .iter()
            .any(|v| v != "self" && v != "shared_session")
        {
            return Err(failure(ErrorClass::Invalid, "invalid_reply_policy"));
        }
        for scope in &self.native_scopes {
            if scope != "*" {
                let parsed = crate::NativeAddress::parse(&format!("{scope}/probe"))
                    .map_err(|_| failure(ErrorClass::Invalid, "invalid_native_scope"))?;
                let canonical = parsed.to_canonical_string();
                if canonical.strip_suffix("/probe") != Some(scope.as_str()) {
                    return Err(failure(ErrorClass::Invalid, "invalid_native_scope"));
                }
            }
        }
        Ok(())
    }
}

/// Bounded durable identity capacities; closing a route never frees its
/// retained conflict/tombstone identity, and no field imposes a job TTL.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UniversalLimits {
    /// Global simultaneously open, unexpired return routes.
    pub max_open_routes: usize,
    /// Global retained return-route identities, including closed routes.
    pub max_retained_routes: usize,
    /// Global retained registration requests and their evidence-use facts.
    pub max_registration_requests: usize,
    /// Global producer lifetime identities, including unopened tombstones.
    pub max_delivery_scopes: usize,
    /// Global immutable close/retirement request receipt identities.
    pub max_lifecycle_requests: usize,
}
impl Default for UniversalLimits {
    /// Conservative finite defaults; operators may raise them without eviction.
    fn default() -> Self {
        Self {
            max_open_routes: 10_000,
            max_retained_routes: 100_000,
            max_registration_requests: 1_000_000,
            max_delivery_scopes: 100_000,
            max_lifecycle_requests: 1_000_000,
        }
    }
}
impl UniversalLimits {
    /// Refuses zero, overflow or an open cap greater than retained route cap.
    pub fn validate(&self) -> Result<(), ApiError> {
        if [
            self.max_open_routes,
            self.max_retained_routes,
            self.max_registration_requests,
            self.max_delivery_scopes,
            self.max_lifecycle_requests,
        ]
        .iter()
        .any(|v| *v == 0 || u64::try_from(*v).unwrap_or(u64::MAX) > crate::MAX_SQLITE_INT)
            || self.max_open_routes > self.max_retained_routes
        {
            return Err(failure(ErrorClass::Invalid, "invalid_universal_limits"));
        }
        Ok(())
    }
}

/// A validated credential-independent policy view; private grant bytes prevent
/// adapters from reading credential material or manufacturing an auth handle.
pub struct ProducerPolicyGrant {
    /// Validated deployment grant, including its private in-memory credential.
    grant: GrantConfig,
}
impl std::fmt::Debug for ProducerPolicyGrant {
    /// Only configured identity and permission counts; credentials stay redacted.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProducerPolicyGrant")
            .field("producer", &self.grant.publisher)
            .finish_non_exhaustive()
    }
}
impl ProducerPolicyGrant {
    /// Authenticated stable producer identity; not a model-supplied claim.
    pub fn producer(&self) -> &str {
        &self.grant.publisher
    }
    /// Optional opt-in policy; absence denies new v1 mutations.
    pub fn policy(&self) -> Option<&ProducerPolicy> {
        self.grant.producer_v1.as_ref()
    }
    /// Current declared native store scopes, empty when v1 is disabled.
    pub fn native_scopes(&self) -> &[String] {
        self.policy().map_or(&[], |p| p.native_scopes.as_slice())
    }
    /// Current mode allowlist, with generic core mode spellings.
    pub fn modes(&self) -> &[String] {
        &self.grant.modes
    }
    /// Current kind allowlist; v1 additionally understands explicit `*`.
    pub fn kinds(&self) -> &[String] {
        &self.grant.kinds
    }
    /// Current generic coalescing policy allowlist.
    pub fn policies(&self) -> &[String] {
        &self.grant.policies
    }
    /// Explicit reply permissions, empty when v1 is disabled.
    pub fn reply_policies(&self) -> &[String] {
        self.policy().map_or(&[], |p| p.reply_policies.as_slice())
    }
    /// Configured audience permission names, never consumer business types.
    pub fn assertion_audiences(&self) -> &[String] {
        self.policy()
            .map_or(&[], |p| p.assertion_audiences.as_slice())
    }
    /// Checks an exact canonical recipient or explicit unrestricted recipient.
    pub fn allows_recipient(&self, address: &str) -> bool {
        allowed(&self.grant.recipients, address)
    }
    /// Checks the caller's exact store prefix without parsing producer semantics.
    pub fn allows_native_scope(&self, address: &crate::NativeAddress) -> bool {
        let text = address.to_canonical_string();
        let prefix = text.rsplit_once('/').map_or("", |(prefix, _)| prefix);
        allowed(self.native_scopes(), prefix)
    }
}

/// The single immutable credential/policy authority shared by both ingress
/// paths during one boot. It has no durable credential or policy representation.
pub struct ProducerAuthorizer {
    /// Validated private in-memory grants; tokens are unique within this boot.
    grants: Vec<ProducerPolicyGrant>,
}
impl std::fmt::Debug for ProducerAuthorizer {
    /// Prints only grant count, never credentials or deployment contents.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProducerAuthorizer")
            .field("grants", &self.grants.len())
            .finish()
    }
}
impl ProducerAuthorizer {
    /// Validates and owns one immutable boot policy; malformed/duplicate tokens
    /// refuse before any ingress can serve requests.
    pub fn new(grants: &[GrantConfig]) -> Result<Self, ApiError> {
        let mut result = Vec::new();
        for (index, grant) in grants.iter().enumerate() {
            grant
                .validate()
                .map_err(|_| failure(ErrorClass::Invalid, "invalid_grant"))?;
            if grants[..index].iter().any(|g| g.token == grant.token) {
                return Err(failure(ErrorClass::Invalid, "duplicate_credential"));
            }
            result.push(ProducerPolicyGrant {
                grant: grant.clone(),
            });
        }
        Ok(Self { grants: result })
    }
    /// Authenticates a nonoperator producer using constant-time comparison;
    /// revoked/unknown/operator credentials never disclose producer records.
    pub fn authenticate(&self, credential: &str) -> Result<&ProducerPolicyGrant, ApiError> {
        let mut matched = None;
        for grant in &self.grants {
            if crate::service::constant_time_eq(credential.as_bytes(), grant.grant.token.as_bytes())
            {
                matched = Some(grant);
            }
        }
        matched
            .filter(|g| !g.grant.admin)
            .ok_or_else(|| failure(ErrorClass::Auth, "invalid_producer_credential"))
    }
    /// Reuses the same boot authority for unchanged legacy operator/publisher
    /// auth; this crate-only view cannot leak credentials to native adapters.
    pub(crate) fn authenticate_legacy(&self, credential: &str) -> Option<&GrantConfig> {
        let mut matched = None;
        for grant in &self.grants {
            if crate::service::constant_time_eq(credential.as_bytes(), grant.grant.token.as_bytes())
            {
                matched = Some(&grant.grant);
            }
        }
        matched
    }
}
impl crate::Storage {
    /// Validates and installs finite v1 capacities. Tightening never evicts
    /// accepted identities; over-cap stores refuse only future admission.
    pub fn configure_universal_limits(&mut self, limits: UniversalLimits) -> Result<(), ApiError> {
        limits.validate()?;
        self.universal_limits = limits;
        Ok(())
    }
    /// Returns the configured identity capacities without occupancy disclosure.
    pub fn universal_limits(&self) -> UniversalLimits {
        self.universal_limits
    }
    /// Installs the single per-boot authority; the same Arc is idempotent,
    /// replacing it refuses. Bare fixture stores initially have no authority.
    pub fn install_producer_authorizer(
        &mut self,
        authorizer: Arc<ProducerAuthorizer>,
    ) -> Result<(), ApiError> {
        if self
            .producer_authorizer
            .as_ref()
            .is_some_and(|old| !Arc::ptr_eq(old, &authorizer))
        {
            return Err(failure(ErrorClass::Conflict, "authority_already_installed"));
        }
        self.producer_authorizer = Some(authorizer);
        Ok(())
    }
    /// Clones the shared authority handle; never creates a second policy store.
    pub fn producer_authorizer(&self) -> Result<Arc<ProducerAuthorizer>, ApiError> {
        self.producer_authorizer
            .clone()
            .ok_or_else(|| failure(ErrorClass::Unavailable, "producer_authority_unavailable"))
    }
}

/// Checks one bounded opaque string without product interpretation.
pub(crate) fn opaque(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
/// Exact generic allowlist matching; wildcard is explicit deployment policy.
pub(crate) fn allowed(values: &[String], value: &str) -> bool {
    values.iter().any(|v| v == "*" || v == value)
}
/// Produces static secret-safe API errors; mutation callers add their stable
/// effect/reconciliation fields at the owning transaction boundary.
pub(crate) fn failure(class: ErrorClass, reason: &str) -> ApiError {
    ApiError {
        class,
        reason: reason.into(),
        retry_hint: RetryHint::Never,
        effect: None,
        reconciliation: None,
        detail: "Bridge refused this request.".into(),
    }
}
