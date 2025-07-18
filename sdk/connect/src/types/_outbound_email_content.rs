// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about email body content.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OutboundEmailContent {
    /// <p>The message source type, that is, <code>RAW</code> or <code>TEMPLATE</code>.</p>
    pub message_source_type: crate::types::OutboundMessageSourceType,
    /// <p>Information about template message configuration.</p>
    pub templated_message_config: ::std::option::Option<crate::types::TemplatedMessageConfig>,
    /// <p>The raw email body content.</p>
    pub raw_message: ::std::option::Option<crate::types::OutboundRawMessage>,
}
impl OutboundEmailContent {
    /// <p>The message source type, that is, <code>RAW</code> or <code>TEMPLATE</code>.</p>
    pub fn message_source_type(&self) -> &crate::types::OutboundMessageSourceType {
        &self.message_source_type
    }
    /// <p>Information about template message configuration.</p>
    pub fn templated_message_config(&self) -> ::std::option::Option<&crate::types::TemplatedMessageConfig> {
        self.templated_message_config.as_ref()
    }
    /// <p>The raw email body content.</p>
    pub fn raw_message(&self) -> ::std::option::Option<&crate::types::OutboundRawMessage> {
        self.raw_message.as_ref()
    }
}
impl OutboundEmailContent {
    /// Creates a new builder-style object to manufacture [`OutboundEmailContent`](crate::types::OutboundEmailContent).
    pub fn builder() -> crate::types::builders::OutboundEmailContentBuilder {
        crate::types::builders::OutboundEmailContentBuilder::default()
    }
}

/// A builder for [`OutboundEmailContent`](crate::types::OutboundEmailContent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OutboundEmailContentBuilder {
    pub(crate) message_source_type: ::std::option::Option<crate::types::OutboundMessageSourceType>,
    pub(crate) templated_message_config: ::std::option::Option<crate::types::TemplatedMessageConfig>,
    pub(crate) raw_message: ::std::option::Option<crate::types::OutboundRawMessage>,
}
impl OutboundEmailContentBuilder {
    /// <p>The message source type, that is, <code>RAW</code> or <code>TEMPLATE</code>.</p>
    /// This field is required.
    pub fn message_source_type(mut self, input: crate::types::OutboundMessageSourceType) -> Self {
        self.message_source_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The message source type, that is, <code>RAW</code> or <code>TEMPLATE</code>.</p>
    pub fn set_message_source_type(mut self, input: ::std::option::Option<crate::types::OutboundMessageSourceType>) -> Self {
        self.message_source_type = input;
        self
    }
    /// <p>The message source type, that is, <code>RAW</code> or <code>TEMPLATE</code>.</p>
    pub fn get_message_source_type(&self) -> &::std::option::Option<crate::types::OutboundMessageSourceType> {
        &self.message_source_type
    }
    /// <p>Information about template message configuration.</p>
    pub fn templated_message_config(mut self, input: crate::types::TemplatedMessageConfig) -> Self {
        self.templated_message_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about template message configuration.</p>
    pub fn set_templated_message_config(mut self, input: ::std::option::Option<crate::types::TemplatedMessageConfig>) -> Self {
        self.templated_message_config = input;
        self
    }
    /// <p>Information about template message configuration.</p>
    pub fn get_templated_message_config(&self) -> &::std::option::Option<crate::types::TemplatedMessageConfig> {
        &self.templated_message_config
    }
    /// <p>The raw email body content.</p>
    pub fn raw_message(mut self, input: crate::types::OutboundRawMessage) -> Self {
        self.raw_message = ::std::option::Option::Some(input);
        self
    }
    /// <p>The raw email body content.</p>
    pub fn set_raw_message(mut self, input: ::std::option::Option<crate::types::OutboundRawMessage>) -> Self {
        self.raw_message = input;
        self
    }
    /// <p>The raw email body content.</p>
    pub fn get_raw_message(&self) -> &::std::option::Option<crate::types::OutboundRawMessage> {
        &self.raw_message
    }
    /// Consumes the builder and constructs a [`OutboundEmailContent`](crate::types::OutboundEmailContent).
    /// This method will fail if any of the following fields are not set:
    /// - [`message_source_type`](crate::types::builders::OutboundEmailContentBuilder::message_source_type)
    pub fn build(self) -> ::std::result::Result<crate::types::OutboundEmailContent, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::OutboundEmailContent {
            message_source_type: self.message_source_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "message_source_type",
                    "message_source_type was not specified but it is required when building OutboundEmailContent",
                )
            })?,
            templated_message_config: self.templated_message_config,
            raw_message: self.raw_message,
        })
    }
}
