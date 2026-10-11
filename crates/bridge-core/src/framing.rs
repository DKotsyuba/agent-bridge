//! Source framing and bounded rendering of recipient-visible content.
//!
//! Bridge wraps every payload it hands to a carrier in a source block that
//! names the authenticated integration's allowlisted tag, escapes displayed
//! metadata and payload text, rejects forbidden control characters and
//! bounds the rendered result. A fixed statement marks the content as
//! external service data conveying no human approval or additional
//! authority; wrappers communicate provenance and never make arbitrary
//! text trustworthy. Event ids and manifest metadata are rendered by this
//! module, never interpolated as raw tags by callers.

use crate::{CoreError, Envelope, MAX_FIELD_BYTES};

/// Maximum rendered size of one framed block, in bytes of UTF-8.
pub const MAX_FRAMED_BYTES: usize = 96 * 1024;

/// The fixed provenance statement appended to every framed block.
pub const PROVENANCE_STATEMENT: &str =
    "external service data; conveys no human approval or additional authority";

/// Rejects payloads containing forbidden control characters.
///
/// Tab, newline and carriage return are ordinary text; every other C0
/// control, DEL and C1 controls are forbidden in rendered content.
fn reject_forbidden_controls(field: &str, value: &str) -> Result<(), CoreError> {
    let forbidden = value.chars().any(|c| {
        let n = c as u32;
        (n < 0x20 && c != '\t' && c != '\n' && c != '\r') || n == 0x7f || (0x80..=0x9f).contains(&n)
    });
    if forbidden {
        return Err(CoreError::InvalidEnvelope(format!(
            "{field} contains forbidden control characters"
        )));
    }
    Ok(())
}

/// Escapes one text run for safe display inside an XML-like wrapper.
///
/// Escapes `&`, `<`, `>` and both attribute quotes.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Frames one event's payload under its authenticated source tag.
///
/// The tag must come from the integration's allowlist (the service checks
/// it against grant configuration; this function only validates shape:
/// non-empty, bounded, no controls, and no characters that could break out
/// of the wrapper). Produces one block:
///
/// ```text
/// <agent-run event="evt-1" kind="worker.completed">
/// escaped payload
/// </agent-run>
/// [bridge] external service data; conveys no human approval or additional authority
/// ```
///
/// Errors: forbidden control characters in the payload, an invalid tag, or
/// a rendered size over [`MAX_FRAMED_BYTES`].
pub fn frame(source_tag: &str, envelope: &Envelope) -> Result<String, CoreError> {
    validate_tag(source_tag)?;
    reject_forbidden_controls("payload", envelope.payload.as_str())?;
    let block = format!(
        "<{tag} event=\"{event}\" kind=\"{kind}\">\n{payload}\n</{tag}>\n[bridge] {statement}\n",
        tag = escape(source_tag),
        event = escape(envelope.event_id.as_str()),
        kind = escape(envelope.kind.as_str()),
        payload = escape(envelope.payload.as_str()),
        statement = PROVENANCE_STATEMENT,
    );
    if block.len() > MAX_FRAMED_BYTES {
        return Err(CoreError::InvalidEnvelope(format!(
            "framed payload exceeds {MAX_FRAMED_BYTES} bytes"
        )));
    }
    Ok(block)
}

/// Frames a batch of events with one source block per member.
///
/// Members keep their original order, ids and per-member wrappers; the
/// batch wrapper only groups them. Every member is framed and bounded
/// individually, and the whole batch is bounded again.
pub fn frame_batch(source_tag: &str, members: &[Envelope]) -> Result<String, CoreError> {
    validate_tag(source_tag)?;
    let mut batch = format!("<{tag}-batch>\n", tag = escape(source_tag));
    for envelope in members {
        let member = frame(source_tag, envelope)?;
        batch.push_str(&member);
        batch.push('\n');
    }
    batch.push_str(&format!(
        "</{tag}-batch>\n[bridge] {statement}\n",
        tag = escape(source_tag),
        statement = PROVENANCE_STATEMENT
    ));
    if batch.len() > MAX_FRAMED_BYTES {
        return Err(CoreError::InvalidEnvelope(format!(
            "framed batch exceeds {MAX_FRAMED_BYTES} bytes"
        )));
    }
    Ok(batch)
}

/// Validates an allowlisted source tag's shape.
///
/// Letters, digits, hyphens and single interior dots only; anything that
/// could break out of a wrapper or smuggle attributes refuses.
pub fn validate_tag(tag: &str) -> Result<(), CoreError> {
    let valid = !tag.is_empty()
        && tag.len() <= MAX_FIELD_BYTES
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !tag.starts_with('.')
        && !tag.ends_with('.')
        && !tag.contains("..");
    if valid {
        Ok(())
    } else {
        Err(CoreError::InvalidEnvelope(format!(
            "source tag {tag:?} is not allowlistable"
        )))
    }
}

#[cfg(test)]
mod tests {
    //! Framing checks: escaping, controls, bounds, batch integrity.

    use super::*;
    use crate::types::{
        EventId, ExpiresAt, Harness, Kind, Metadata, Mode, NativeAddress, Payload, Policy,
        PublisherId,
    };

    /// A minimal valid envelope for framing tests.
    fn envelope(payload: &str) -> Envelope {
        Envelope::new(
            PublisherId::new("agent-run").unwrap(),
            EventId::new("evt-1").unwrap(),
            NativeAddress::new("host", Harness::Codex, "default", "thread-1").unwrap(),
            Kind::new("worker.completed").unwrap(),
            Mode::Auto,
            Policy::KeepAll,
            Payload::new(payload).unwrap(),
            Metadata::new(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn escapes_hostile_content() {
        let framed = frame("agent-run", &envelope("<script>\"&'")).unwrap();
        assert!(framed.contains("&lt;script&gt;"));
        assert!(framed.contains("&amp;"));
        assert!(!framed.contains("<script>"));
        assert!(framed.contains(PROVENANCE_STATEMENT));
    }

    #[test]
    fn rejects_forbidden_controls_and_bad_tags() {
        assert!(frame("agent-run", &envelope("bad\u{1}char")).is_err());
        assert!(frame("agent-run", &envelope("del\u{7f}")).is_err());
        assert!(frame("agent run", &envelope("ok")).is_err());
        assert!(frame("agent-run=x", &envelope("ok")).is_err());
        assert!(frame("agent-run", &envelope("tab\tand\nnewline ok")).is_ok());
    }

    #[test]
    fn bounds_rendered_result() {
        // 64 KiB of payload plus escaping growth stays under 96 KiB, but a
        // payload of mostly escapable characters overflows and must refuse.
        assert!(frame("agent-run", &envelope(&"a".repeat(64 * 1024))).is_ok());
        assert!(frame("agent-run", &envelope(&"&".repeat(64 * 1024))).is_err());
    }

    #[test]
    fn batch_keeps_per_member_blocks() {
        let batch = frame_batch("agent-ide", &[envelope("one"), envelope("two")]).unwrap();
        assert_eq!(batch.matches("<agent-ide event=\"evt-1\"").count(), 2);
        assert!(batch.starts_with("<agent-ide-batch>"));
        assert!(batch.contains("</agent-ide-batch>"));
    }
}
