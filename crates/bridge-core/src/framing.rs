//! Source framing and bounded rendering of recipient-visible content.
//!
//! Bridge wraps payloads in escaped, bounded source blocks. Legacy blocks name
//! the authenticated integration's allowlisted tag. Compact Bridge headers
//! show display labels. Every frame conveys no human approval or authority.

mod names;

use std::fmt::Write;

use crate::{CoreError, Envelope};

/// Maximum rendered size of one framed manifest, in bytes of UTF-8.
pub const MAX_FRAMED_BYTES: usize = 96 * 1024;

/// Maximum length of an allowlisted source tag.
///
/// Fixed (rather than the general field bound) so the worst-case rendered
/// size of an event is known at admission, before any tag is chosen.
pub const MAX_TAG_BYTES: usize = 64;

/// The fixed provenance statement appended to legacy blocks and mixed batches.
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
    escape_text(value, true)
}

/// Escapes markup and, for attributes and legacy bodies, both quotes.
fn escape_text(value: &str, quotes: bool) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if quotes => out.push_str("&quot;"),
            '\'' if quotes => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Renders one member block without any size bound.
///
/// Callers validate the tag and bound the result; the payload's forbidden
/// controls are rejected here so no rendering path can skip the check.
fn render_member(
    source_tag: &str,
    envelope: &Envelope,
    accepted_at_ms: u64,
    sender_name: Option<&str>,
) -> Result<String, CoreError> {
    reject_forbidden_controls("payload", envelope.payload.as_str())?;
    if matches!(
        envelope.kind.as_str(),
        "bridge.message" | "bridge.delivery_report"
    ) {
        return Ok(render_compact(envelope, accepted_at_ms, sender_name));
    }
    Ok(render_legacy_member(source_tag, envelope))
}

/// Renders the original source block with full body quoting.
fn render_legacy_member(source_tag: &str, envelope: &Envelope) -> String {
    // `source` is the publisher identity Bridge itself stamped into the
    // envelope at admission (from the authenticated integration grant).
    // It is trusted issuer provenance; caller-supplied metadata never
    // reaches this attribute and can never forge a verified identity.
    format!(
        "<{tag} event=\"{event}\" kind=\"{kind}\" source=\"{source}\">\n{payload}\n</{tag}>\n",
        tag = escape(source_tag),
        event = escape(envelope.event_id.as_str()),
        kind = escape(envelope.kind.as_str()),
        source = escape(envelope.publisher.as_str()),
        payload = escape(envelope.payload.as_str()),
    )
}

/// Returns the display id of a root event or Bridge report with a hex suffix.
pub fn short_id(event_id: &str) -> Option<String> {
    let suffix = event_id
        .strip_prefix("root-")
        .or_else(|| event_id.strip_prefix("feedback-"))?;
    let short = suffix.get(..6)?;
    short
        .bytes()
        .all(|b| b.is_ascii_hexdigit())
        .then(|| format!("#{short}"))
}

/// Renders the compact header and body for the two Bridge kinds.
fn render_compact(envelope: &Envelope, accepted_at_ms: u64, sender_name: Option<&str>) -> String {
    let receipt = envelope.kind.as_str() == "bridge.delivery_report";
    let from = if receipt {
        "Bridge".into()
    } else {
        // One rule for every path: the generated name depends only on the stamped
        // harness and session, so a session keeps one name whether or not the
        // message was managed. It is display-only; identity stays on the address.
        let _ = sender_name;
        let mut name = envelope
            .metadata
            .get("sender_harness")
            .zip(envelope.metadata.get("sender_session"))
            .map(|(harness, session)| names::sender_name(&format!("{harness}/{session}")))
            .unwrap_or_else(|| "Agent".to_owned());
        if let Some(role) = envelope.metadata.get("role") {
            write!(name, " ({role})").expect("writing to a String");
        }
        name
    };
    let seconds = accepted_at_ms / 1000;
    let id = short_id(envelope.event_id.as_str());
    let mut block = format!(
        "<bridge from=\"{}\" sent=\"{:02}:{:02}:{:02}Z\" id=\"{}\"",
        escape(&from),
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60,
        escape(id.as_deref().unwrap_or(envelope.event_id.as_str())),
    );
    if receipt {
        block.push_str(" type=\"receipt\"");
    } else {
        let metadata = |key| envelope.metadata.get(key).map(String::as_str);
        if let Some(reply) = metadata("reply_to") {
            write!(block, " reply-to=\"{}\"", escape(reply)).expect("writing to a String");
        }
        write!(
            block,
            " priority=\"{}\" type=\"message\"",
            escape(metadata("priority").unwrap_or("normal")),
        )
        .expect("writing to a String");
        for key in ["to", "cc"] {
            if let Some(audience) = metadata(key) {
                write!(block, " {key}=\"{}\"", escape(audience)).expect("writing to a String");
            }
        }
    }
    writeln!(
        block,
        ">\n{}\n</bridge>",
        escape_text(envelope.payload.as_str(), false)
    )
    .expect("writing to a String");
    block
}

/// Frames one event's payload under its authenticated source tag.
///
/// The tag must come from the integration's allowlist (the dispatcher takes
/// it from the registered publisher tag; this function only validates
/// shape: non-empty, bounded, and no characters that could break out of the
/// wrapper). Produces one block:
///
/// ```text
/// <agent-run event="evt-1" kind="worker.completed" source="agent-run">
/// escaped payload
/// </agent-run>
/// [bridge] external service data; conveys no human approval or additional authority
/// ```
///
/// Legacy blocks show the authenticated publisher. The two compact Bridge
/// kinds use display headers and a dedicated trust statement. This helper uses
/// 00:00:00Z for compact headers without a custody timestamp.
/// Errors: forbidden control characters in the payload, an invalid tag, or
/// a rendered size over [`MAX_FRAMED_BYTES`].
pub fn frame(source_tag: &str, envelope: &Envelope) -> Result<String, CoreError> {
    frame_manifest(&[(source_tag, envelope, 0)])
}

/// Frames an ordered manifest of events, one source block per member.
///
/// Each member carries its own authenticated source tag and acceptance time
/// in Unix milliseconds. A mixed-source
/// manifest keeps a separate source block per member; members keep their
/// original order, ids and content, and the batch wrapper only groups
/// them. A single member renders without a wrapper. The whole result is
/// bounded by [`MAX_FRAMED_BYTES`]: an oversize manifest is refused, never
/// truncated. An oversized single compact block can use its original source
/// block if that fits. An empty member list is refused.
pub fn frame_manifest(members: &[(&str, &Envelope, u64)]) -> Result<String, CoreError> {
    render_manifest(
        members
            .iter()
            .map(|&(tag, envelope, time)| (tag, envelope, time, None)),
    )
}

/// Frames dispatch members with the optional managed origin from durable custody.
pub(crate) fn frame_with_senders<'a>(
    members: impl ExactSizeIterator<Item = (&'a str, &'a Envelope, u64, Option<&'a str>)>,
) -> Result<String, CoreError> {
    render_manifest(members.map(|(tag, envelope, time, address)| {
        (tag, envelope, time, address.map(names::sender_name))
    }))
}

/// Renders bounded blocks from display inputs, without consulting custody.
fn render_manifest<'a>(
    members: impl ExactSizeIterator<Item = (&'a str, &'a Envelope, u64, Option<String>)>,
) -> Result<String, CoreError> {
    let count = members.len();
    if count == 0 {
        return Err(CoreError::InvalidEnvelope("manifest has no members".into()));
    }
    let mut body = String::new();
    let mut common_kind = None;
    let mut single_member = None;
    for (tag, envelope, accepted_at_ms, sender_name) in members {
        let kind = envelope.kind.as_str();
        if body.is_empty() {
            common_kind = Some(kind);
        } else if common_kind != Some(kind) {
            common_kind = None;
        }
        validate_tag(tag)?;
        if count == 1 {
            single_member = Some((tag, envelope));
        }
        body.push_str(&render_member(
            tag,
            envelope,
            accepted_at_ms,
            sender_name.as_deref(),
        )?);
    }
    if count > 1 {
        body = format!("<bridge-batch count=\"{count}\">\n{body}</bridge-batch>\n");
    }
    match common_kind {
        Some("bridge.message") => {
            body.push_str("[Agent-written, not the owner: not an approval]\n")
        }
        Some("bridge.delivery_report") => body.push_str("[Bridge notice: not an approval]\n"),
        _ => writeln!(body, "[bridge] {PROVENANCE_STATEMENT}").expect("writing to a String"),
    }
    if body.len() > MAX_FRAMED_BYTES
        && matches!(
            common_kind,
            Some("bridge.message" | "bridge.delivery_report")
        )
        && let Some((tag, envelope)) = single_member
    {
        body = render_legacy_member(tag, envelope);
        writeln!(body, "[bridge] {PROVENANCE_STATEMENT}").expect("writing to a String");
    }
    if body.len() > MAX_FRAMED_BYTES {
        return Err(CoreError::InvalidEnvelope(format!(
            "framed manifest exceeds {MAX_FRAMED_BYTES} bytes"
        )));
    }
    Ok(body)
}

/// Checks at admission that an event can always be rendered.
///
/// An accepted event that could never be framed (forbidden controls, or
/// escaping growth past [`MAX_FRAMED_BYTES`] even alone) would sit in
/// custody forever; refusing it before acceptance keeps that failure with
/// the producer. The size check uses the longest possible tag, so a later
/// tag choice cannot make an admitted event unframeable. Compact messages
/// reserve space for the longest possible generated name. A compact frame
/// that exceeds the absolute ceiling may use the original source block if
/// that fits, preserving custody and handoff for pre-upgrade envelopes.
pub fn check_renderable(envelope: &Envelope) -> Result<(), CoreError> {
    let widest_tag = "a".repeat(MAX_TAG_BYTES);
    let name = (envelope.kind.as_str() == "bridge.message").then(names::widest_name);
    render_manifest([(widest_tag.as_str(), envelope, 0, name)].into_iter()).map(|_| ())
}

/// Validates an allowlisted source tag's shape.
///
/// Letters, digits, hyphens and single interior dots only, at most
/// [`MAX_TAG_BYTES`]; anything that could break out of a wrapper or smuggle
/// attributes refuses.
pub fn validate_tag(tag: &str) -> Result<(), CoreError> {
    let valid = !tag.is_empty()
        && tag.len() <= MAX_TAG_BYTES
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
    //! Framing checks: escaping, controls, bounds, manifest integrity.

    use super::*;
    use crate::types::{
        EventId, Harness, Kind, Metadata, Mode, NativeAddress, Payload, Policy, PublisherId,
    };

    /// A minimal valid envelope for framing tests.
    fn envelope(id: &str, payload: &str) -> Envelope {
        Envelope::new(
            PublisherId::new("agent-run").unwrap(),
            EventId::new(id).unwrap(),
            NativeAddress::new("host", Harness::CODEX, "default", "thread-1").unwrap(),
            Kind::new("worker.completed").unwrap(),
            Mode::Auto,
            Policy::KeepAll,
            Payload::new(payload).unwrap(),
            Metadata::new(),
            None,
        )
        .unwrap()
    }

    /// Compact messages preserve body quotes and fully escape header attributes.
    #[test]
    fn compact_message_golden() {
        let mut message = envelope("root-abcdef1234", r#"{"body":"<&>'"}"#);
        message.kind = Kind::new("bridge.message").unwrap();
        message.metadata.extend([
            ("role".into(), r#""<&>'"#.into()),
            ("reply_to".into(), "#Aa012F".into()),
            ("priority".into(), "urgent".into()),
            ("to".into(), "One & Two".into()),
            ("cc".into(), "Three".into()),
            ("sender_harness".into(), "claude".into()),
            ("sender_session".into(), "session".into()),
        ]);
        let name = names::sender_name("claude/session");
        let framed = frame_with_senders(
            [(
                "bridge-root",
                &message,
                90_123_999,
                Some("example/claude/default/session"),
            )]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(
            framed,
            format!(
                concat!(
                    "<bridge from=\"{} (&quot;&lt;&amp;&gt;&#39;)\" sent=\"01:02:03Z\" id=\"#abcdef\" reply-to=\"#Aa012F\" priority=\"urgent\" type=\"message\" to=\"One &amp; Two\" cc=\"Three\">\n",
                    "{{\"body\":\"&lt;&amp;&gt;'\"}}\n",
                    "</bridge>\n",
                    "[Agent-written, not the owner: not an approval]\n",
                ),
                name
            )
        );
    }

    /// A session keeps one name whether or not the message is managed.
    #[test]
    fn managed_and_unmanaged_share_name() {
        let mut message = envelope("root-1234567890", "Ready.");
        message.kind = Kind::new("bridge.message").unwrap();
        message.metadata.extend([
            ("role".into(), "reviewer".into()),
            ("sender_harness".into(), "codex".into()),
            ("sender_session".into(), "session".into()),
        ]);
        let unmanaged = frame_manifest(&[("bridge-root", &message, 1_000)]).unwrap();
        let managed = frame_with_senders(
            [(
                "bridge-root",
                &message,
                1_000,
                Some("example/codex/default/session"),
            )]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(managed, unmanaged);
        assert!(unmanaged.starts_with(&format!(
            "<bridge from=\"{} (reviewer)\"",
            names::sender_name("codex/session")
        )));
    }

    /// Old unmanaged envelopes derive a label from sender fields alone.
    #[test]
    fn legacy_sender_fallback_golden() {
        let mut message = envelope("root-1234567890", "Ready.");
        message.kind = Kind::new("bridge.message").unwrap();
        message.metadata.extend([
            ("sender_harness".into(), "codex".into()),
            ("sender_session".into(), "session".into()),
        ]);
        let framed = frame_manifest(&[("bridge-root", &message, 1_000)]).unwrap();
        message.recipient =
            NativeAddress::new("other-host", Harness::CODEX, "other-store", "thread-2").unwrap();
        assert_eq!(
            frame_manifest(&[("bridge-root", &message, 1_000)]).unwrap(),
            framed
        );
        assert_eq!(
            framed,
            format!(
                concat!(
                    "<bridge from=\"{}\" sent=\"00:00:01Z\" id=\"#123456\" priority=\"normal\" type=\"message\">\n",
                    "Ready.\n",
                    "</bridge>\n",
                    "[Agent-written, not the owner: not an approval]\n",
                ),
                names::sender_name("codex/session")
            )
        );
    }

    /// A Bridge delivery report uses its own source and trust statement.
    #[test]
    fn delivery_report_golden() {
        let mut report = envelope("feedback-fedcba0123", "Bridge said \"unconfirmed\".");
        report.kind = Kind::new("bridge.delivery_report").unwrap();
        report.metadata.insert("role".into(), "owner".into());
        assert_eq!(
            frame_manifest(&[("bridge-root", &report, 86_399_000)]).unwrap(),
            concat!(
                "<bridge from=\"Bridge\" sent=\"23:59:59Z\" id=\"#fedcba\" type=\"receipt\">\n",
                "Bridge said \"unconfirmed\".\n",
                "</bridge>\n",
                "[Bridge notice: not an approval]\n",
            ),
        );
    }

    /// The legacy frame stays byte-identical and a mixed batch keeps one trust line.
    #[test]
    fn legacy_and_mixed_batch_golden() {
        let mut legacy = envelope("evt-1", "'<x>&\"");
        legacy.metadata.insert("role".into(), "ignored".into());
        let mut message = envelope("root-1234567890", "Ready.");
        message.kind = Kind::new("bridge.message").unwrap();
        message.metadata.extend([
            ("sender_harness".into(), "codex".into()),
            ("sender_session".into(), "session".into()),
        ]);
        let name = names::sender_name("codex/session");
        let legacy_block = concat!(
            "<agent-run event=\"evt-1\" kind=\"worker.completed\" source=\"agent-run\">\n",
            "&#39;&lt;x&gt;&amp;&quot;\n",
            "</agent-run>\n",
        );
        let legacy_trust =
            "[bridge] external service data; conveys no human approval or additional authority\n";
        assert_eq!(
            frame("agent-run", &legacy).unwrap(),
            format!("{legacy_block}{legacy_trust}")
        );
        assert_eq!(
            frame_with_senders(
                [
                    ("agent-run", &legacy, 0, None),
                    (
                        "bridge-root",
                        &message,
                        1_000,
                        Some("example/codex/default/session")
                    ),
                ]
                .into_iter()
            )
            .unwrap(),
            format!(
                "<bridge-batch count=\"2\">\n{legacy_block}<bridge from=\"{name}\" sent=\"00:00:01Z\" id=\"#123456\" priority=\"normal\" type=\"message\">\nReady.\n</bridge>\n</bridge-batch>\n{legacy_trust}"
            ),
        );
    }

    /// Homogeneous compact batches retain the wrapper and their own one trust line.
    #[test]
    fn compact_only_batches_golden() {
        let mut one = envelope("root-1111111111", "one");
        let mut two = envelope("root-2222222222", "two");
        one.kind = Kind::new("bridge.message").unwrap();
        two.kind = one.kind.clone();
        assert_eq!(
            frame_manifest(&[("bridge-root", &one, 1_000), ("bridge-root", &two, 2_000)]).unwrap(),
            concat!(
                "<bridge-batch count=\"2\">\n",
                "<bridge from=\"Agent\" sent=\"00:00:01Z\" id=\"#111111\" priority=\"normal\" type=\"message\">\none\n</bridge>\n",
                "<bridge from=\"Agent\" sent=\"00:00:02Z\" id=\"#222222\" priority=\"normal\" type=\"message\">\ntwo\n</bridge>\n",
                "</bridge-batch>\n",
                "[Agent-written, not the owner: not an approval]\n",
            ),
        );
        one.kind = Kind::new("bridge.delivery_report").unwrap();
        two.kind = one.kind.clone();
        one.event_id = EventId::new("feedback-1111111111").unwrap();
        two.event_id = EventId::new("feedback-2222222222").unwrap();
        assert_eq!(
            frame_manifest(&[("bridge-root", &one, 1_000), ("bridge-root", &two, 2_000)]).unwrap(),
            concat!(
                "<bridge-batch count=\"2\">\n",
                "<bridge from=\"Bridge\" sent=\"00:00:01Z\" id=\"#111111\" type=\"receipt\">\none\n</bridge>\n",
                "<bridge from=\"Bridge\" sent=\"00:00:02Z\" id=\"#222222\" type=\"receipt\">\ntwo\n</bridge>\n",
                "</bridge-batch>\n",
                "[Bridge notice: not an approval]\n",
            ),
        );
    }

    /// Hostile markup in the payload is escaped and the fixed provenance
    /// statement is present.
    #[test]
    fn escapes_hostile_content() {
        let framed = frame("agent-run", &envelope("evt-1", "<script>\"&'")).unwrap();
        assert!(framed.contains("&lt;script&gt;"));
        assert!(framed.contains("&amp;"));
        assert!(!framed.contains("<script>"));
        assert!(framed.contains(PROVENANCE_STATEMENT));
    }

    /// Forbidden control characters and non-allowlistable tags refuse the
    /// framing; ordinary tabs and newlines pass.
    #[test]
    fn rejects_forbidden_controls_and_bad_tags() {
        assert!(frame("agent-run", &envelope("e", "bad\u{1}char")).is_err());
        assert!(frame("agent-run", &envelope("e", "del\u{7f}")).is_err());
        assert!(frame("agent run", &envelope("e", "ok")).is_err());
        assert!(frame("agent-run=x", &envelope("e", "ok")).is_err());
        assert!(frame(&"t".repeat(MAX_TAG_BYTES + 1), &envelope("e", "ok")).is_err());
        assert!(frame("agent-run", &envelope("e", "tab\tand\nnewline ok")).is_ok());
    }

    /// Oversize rendered results refuse instead of truncating, while a
    /// full-size plain payload still fits.
    #[test]
    fn bounds_rendered_result_without_truncating() {
        assert!(frame("agent-run", &envelope("e", &"a".repeat(64 * 1024))).is_ok());
        assert!(frame("agent-run", &envelope("e", &"&".repeat(64 * 1024))).is_err());
        assert!(check_renderable(&envelope("e", &"&".repeat(64 * 1024))).is_err());
        assert!(check_renderable(&envelope("e", "fine")).is_ok());
    }

    /// A manifest renders one source block per member, preserving order
    /// and per-member identity.
    #[test]
    fn manifest_keeps_a_separate_source_block_per_member() {
        let one = envelope("evt-1", "one");
        let two = envelope("evt-2", "two");
        let batch = frame_manifest(&[("agent-ide", &one, 0), ("agent-run", &two, 0)]).unwrap();
        assert_eq!(batch.matches("<agent-ide event=\"evt-1\"").count(), 1);
        assert_eq!(batch.matches("<agent-run event=\"evt-2\"").count(), 1);
        assert!(batch.starts_with("<bridge-batch count=\"2\">"));
        assert!(batch.find("evt-1").unwrap() < batch.find("evt-2").unwrap());
        assert!(frame_manifest(&[]).is_err());
    }
}
