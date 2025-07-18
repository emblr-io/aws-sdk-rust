// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A short summary and metadata for a managed notification event.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ManagedSourceEventMetadataSummary {
    /// <p>The Region where the notification originated.</p>
    pub event_origin_region: ::std::option::Option<::std::string::String>,
    /// <p>The source service of the notification.</p>
    /// <p>Must match one of the valid EventBridge sources. Only Amazon Web Services service sourced events are supported. For example, <code>aws.ec2</code> and <code>aws.cloudwatch</code>. For more information, see <a href="https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event.html#eb-service-event-delivery-level">Event delivery from Amazon Web Services services</a> in the <i>Amazon EventBridge User Guide</i>.</p>
    pub source: ::std::string::String,
    /// <p>The event Type of the notification.</p>
    pub event_type: ::std::string::String,
}
impl ManagedSourceEventMetadataSummary {
    /// <p>The Region where the notification originated.</p>
    pub fn event_origin_region(&self) -> ::std::option::Option<&str> {
        self.event_origin_region.as_deref()
    }
    /// <p>The source service of the notification.</p>
    /// <p>Must match one of the valid EventBridge sources. Only Amazon Web Services service sourced events are supported. For example, <code>aws.ec2</code> and <code>aws.cloudwatch</code>. For more information, see <a href="https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event.html#eb-service-event-delivery-level">Event delivery from Amazon Web Services services</a> in the <i>Amazon EventBridge User Guide</i>.</p>
    pub fn source(&self) -> &str {
        use std::ops::Deref;
        self.source.deref()
    }
    /// <p>The event Type of the notification.</p>
    pub fn event_type(&self) -> &str {
        use std::ops::Deref;
        self.event_type.deref()
    }
}
impl ManagedSourceEventMetadataSummary {
    /// Creates a new builder-style object to manufacture [`ManagedSourceEventMetadataSummary`](crate::types::ManagedSourceEventMetadataSummary).
    pub fn builder() -> crate::types::builders::ManagedSourceEventMetadataSummaryBuilder {
        crate::types::builders::ManagedSourceEventMetadataSummaryBuilder::default()
    }
}

/// A builder for [`ManagedSourceEventMetadataSummary`](crate::types::ManagedSourceEventMetadataSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ManagedSourceEventMetadataSummaryBuilder {
    pub(crate) event_origin_region: ::std::option::Option<::std::string::String>,
    pub(crate) source: ::std::option::Option<::std::string::String>,
    pub(crate) event_type: ::std::option::Option<::std::string::String>,
}
impl ManagedSourceEventMetadataSummaryBuilder {
    /// <p>The Region where the notification originated.</p>
    pub fn event_origin_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_origin_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Region where the notification originated.</p>
    pub fn set_event_origin_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_origin_region = input;
        self
    }
    /// <p>The Region where the notification originated.</p>
    pub fn get_event_origin_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_origin_region
    }
    /// <p>The source service of the notification.</p>
    /// <p>Must match one of the valid EventBridge sources. Only Amazon Web Services service sourced events are supported. For example, <code>aws.ec2</code> and <code>aws.cloudwatch</code>. For more information, see <a href="https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event.html#eb-service-event-delivery-level">Event delivery from Amazon Web Services services</a> in the <i>Amazon EventBridge User Guide</i>.</p>
    /// This field is required.
    pub fn source(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The source service of the notification.</p>
    /// <p>Must match one of the valid EventBridge sources. Only Amazon Web Services service sourced events are supported. For example, <code>aws.ec2</code> and <code>aws.cloudwatch</code>. For more information, see <a href="https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event.html#eb-service-event-delivery-level">Event delivery from Amazon Web Services services</a> in the <i>Amazon EventBridge User Guide</i>.</p>
    pub fn set_source(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source = input;
        self
    }
    /// <p>The source service of the notification.</p>
    /// <p>Must match one of the valid EventBridge sources. Only Amazon Web Services service sourced events are supported. For example, <code>aws.ec2</code> and <code>aws.cloudwatch</code>. For more information, see <a href="https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event.html#eb-service-event-delivery-level">Event delivery from Amazon Web Services services</a> in the <i>Amazon EventBridge User Guide</i>.</p>
    pub fn get_source(&self) -> &::std::option::Option<::std::string::String> {
        &self.source
    }
    /// <p>The event Type of the notification.</p>
    /// This field is required.
    pub fn event_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The event Type of the notification.</p>
    pub fn set_event_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_type = input;
        self
    }
    /// <p>The event Type of the notification.</p>
    pub fn get_event_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_type
    }
    /// Consumes the builder and constructs a [`ManagedSourceEventMetadataSummary`](crate::types::ManagedSourceEventMetadataSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`source`](crate::types::builders::ManagedSourceEventMetadataSummaryBuilder::source)
    /// - [`event_type`](crate::types::builders::ManagedSourceEventMetadataSummaryBuilder::event_type)
    pub fn build(self) -> ::std::result::Result<crate::types::ManagedSourceEventMetadataSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ManagedSourceEventMetadataSummary {
            event_origin_region: self.event_origin_region,
            source: self.source.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "source",
                    "source was not specified but it is required when building ManagedSourceEventMetadataSummary",
                )
            })?,
            event_type: self.event_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "event_type",
                    "event_type was not specified but it is required when building ManagedSourceEventMetadataSummary",
                )
            })?,
        })
    }
}
