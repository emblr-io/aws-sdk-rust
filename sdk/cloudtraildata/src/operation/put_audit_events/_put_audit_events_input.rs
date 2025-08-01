// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutAuditEventsInput {
    /// <p>The JSON payload of events that you want to ingest. You can also point to the JSON event payload in a file.</p>
    pub audit_events: ::std::option::Option<::std::vec::Vec<crate::types::AuditEvent>>,
    /// <p>The ARN or ID (the ARN suffix) of a channel.</p>
    pub channel_arn: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier that is conditionally required when the channel's resource policy includes an external ID. This value can be any string, such as a passphrase or account number.</p>
    pub external_id: ::std::option::Option<::std::string::String>,
}
impl PutAuditEventsInput {
    /// <p>The JSON payload of events that you want to ingest. You can also point to the JSON event payload in a file.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.audit_events.is_none()`.
    pub fn audit_events(&self) -> &[crate::types::AuditEvent] {
        self.audit_events.as_deref().unwrap_or_default()
    }
    /// <p>The ARN or ID (the ARN suffix) of a channel.</p>
    pub fn channel_arn(&self) -> ::std::option::Option<&str> {
        self.channel_arn.as_deref()
    }
    /// <p>A unique identifier that is conditionally required when the channel's resource policy includes an external ID. This value can be any string, such as a passphrase or account number.</p>
    pub fn external_id(&self) -> ::std::option::Option<&str> {
        self.external_id.as_deref()
    }
}
impl PutAuditEventsInput {
    /// Creates a new builder-style object to manufacture [`PutAuditEventsInput`](crate::operation::put_audit_events::PutAuditEventsInput).
    pub fn builder() -> crate::operation::put_audit_events::builders::PutAuditEventsInputBuilder {
        crate::operation::put_audit_events::builders::PutAuditEventsInputBuilder::default()
    }
}

/// A builder for [`PutAuditEventsInput`](crate::operation::put_audit_events::PutAuditEventsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutAuditEventsInputBuilder {
    pub(crate) audit_events: ::std::option::Option<::std::vec::Vec<crate::types::AuditEvent>>,
    pub(crate) channel_arn: ::std::option::Option<::std::string::String>,
    pub(crate) external_id: ::std::option::Option<::std::string::String>,
}
impl PutAuditEventsInputBuilder {
    /// Appends an item to `audit_events`.
    ///
    /// To override the contents of this collection use [`set_audit_events`](Self::set_audit_events).
    ///
    /// <p>The JSON payload of events that you want to ingest. You can also point to the JSON event payload in a file.</p>
    pub fn audit_events(mut self, input: crate::types::AuditEvent) -> Self {
        let mut v = self.audit_events.unwrap_or_default();
        v.push(input);
        self.audit_events = ::std::option::Option::Some(v);
        self
    }
    /// <p>The JSON payload of events that you want to ingest. You can also point to the JSON event payload in a file.</p>
    pub fn set_audit_events(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AuditEvent>>) -> Self {
        self.audit_events = input;
        self
    }
    /// <p>The JSON payload of events that you want to ingest. You can also point to the JSON event payload in a file.</p>
    pub fn get_audit_events(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AuditEvent>> {
        &self.audit_events
    }
    /// <p>The ARN or ID (the ARN suffix) of a channel.</p>
    /// This field is required.
    pub fn channel_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN or ID (the ARN suffix) of a channel.</p>
    pub fn set_channel_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_arn = input;
        self
    }
    /// <p>The ARN or ID (the ARN suffix) of a channel.</p>
    pub fn get_channel_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_arn
    }
    /// <p>A unique identifier that is conditionally required when the channel's resource policy includes an external ID. This value can be any string, such as a passphrase or account number.</p>
    pub fn external_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.external_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier that is conditionally required when the channel's resource policy includes an external ID. This value can be any string, such as a passphrase or account number.</p>
    pub fn set_external_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.external_id = input;
        self
    }
    /// <p>A unique identifier that is conditionally required when the channel's resource policy includes an external ID. This value can be any string, such as a passphrase or account number.</p>
    pub fn get_external_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.external_id
    }
    /// Consumes the builder and constructs a [`PutAuditEventsInput`](crate::operation::put_audit_events::PutAuditEventsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_audit_events::PutAuditEventsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_audit_events::PutAuditEventsInput {
            audit_events: self.audit_events,
            channel_arn: self.channel_arn,
            external_id: self.external_id,
        })
    }
}
