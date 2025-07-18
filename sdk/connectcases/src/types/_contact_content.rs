// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents a content of an Amazon Connect contact object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ContactContent {
    /// <p>A unique identifier of a contact in Amazon Connect.</p>
    pub contact_arn: ::std::string::String,
    /// <p>A list of channels to filter on for related items of type <code>Contact</code>.</p>
    pub channel: ::std::string::String,
    /// <p>The difference between the <code>InitiationTimestamp</code> and the <code>DisconnectTimestamp</code> of the contact.</p>
    pub connected_to_system_time: ::aws_smithy_types::DateTime,
}
impl ContactContent {
    /// <p>A unique identifier of a contact in Amazon Connect.</p>
    pub fn contact_arn(&self) -> &str {
        use std::ops::Deref;
        self.contact_arn.deref()
    }
    /// <p>A list of channels to filter on for related items of type <code>Contact</code>.</p>
    pub fn channel(&self) -> &str {
        use std::ops::Deref;
        self.channel.deref()
    }
    /// <p>The difference between the <code>InitiationTimestamp</code> and the <code>DisconnectTimestamp</code> of the contact.</p>
    pub fn connected_to_system_time(&self) -> &::aws_smithy_types::DateTime {
        &self.connected_to_system_time
    }
}
impl ContactContent {
    /// Creates a new builder-style object to manufacture [`ContactContent`](crate::types::ContactContent).
    pub fn builder() -> crate::types::builders::ContactContentBuilder {
        crate::types::builders::ContactContentBuilder::default()
    }
}

/// A builder for [`ContactContent`](crate::types::ContactContent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ContactContentBuilder {
    pub(crate) contact_arn: ::std::option::Option<::std::string::String>,
    pub(crate) channel: ::std::option::Option<::std::string::String>,
    pub(crate) connected_to_system_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ContactContentBuilder {
    /// <p>A unique identifier of a contact in Amazon Connect.</p>
    /// This field is required.
    pub fn contact_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.contact_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier of a contact in Amazon Connect.</p>
    pub fn set_contact_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.contact_arn = input;
        self
    }
    /// <p>A unique identifier of a contact in Amazon Connect.</p>
    pub fn get_contact_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.contact_arn
    }
    /// <p>A list of channels to filter on for related items of type <code>Contact</code>.</p>
    /// This field is required.
    pub fn channel(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A list of channels to filter on for related items of type <code>Contact</code>.</p>
    pub fn set_channel(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel = input;
        self
    }
    /// <p>A list of channels to filter on for related items of type <code>Contact</code>.</p>
    pub fn get_channel(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel
    }
    /// <p>The difference between the <code>InitiationTimestamp</code> and the <code>DisconnectTimestamp</code> of the contact.</p>
    /// This field is required.
    pub fn connected_to_system_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.connected_to_system_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The difference between the <code>InitiationTimestamp</code> and the <code>DisconnectTimestamp</code> of the contact.</p>
    pub fn set_connected_to_system_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.connected_to_system_time = input;
        self
    }
    /// <p>The difference between the <code>InitiationTimestamp</code> and the <code>DisconnectTimestamp</code> of the contact.</p>
    pub fn get_connected_to_system_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.connected_to_system_time
    }
    /// Consumes the builder and constructs a [`ContactContent`](crate::types::ContactContent).
    /// This method will fail if any of the following fields are not set:
    /// - [`contact_arn`](crate::types::builders::ContactContentBuilder::contact_arn)
    /// - [`channel`](crate::types::builders::ContactContentBuilder::channel)
    /// - [`connected_to_system_time`](crate::types::builders::ContactContentBuilder::connected_to_system_time)
    pub fn build(self) -> ::std::result::Result<crate::types::ContactContent, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ContactContent {
            contact_arn: self.contact_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "contact_arn",
                    "contact_arn was not specified but it is required when building ContactContent",
                )
            })?,
            channel: self.channel.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "channel",
                    "channel was not specified but it is required when building ContactContent",
                )
            })?,
            connected_to_system_time: self.connected_to_system_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "connected_to_system_time",
                    "connected_to_system_time was not specified but it is required when building ContactContent",
                )
            })?,
        })
    }
}
