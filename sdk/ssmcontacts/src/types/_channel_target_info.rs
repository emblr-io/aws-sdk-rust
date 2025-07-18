// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the contact channel that Incident Manager uses to engage the contact.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ChannelTargetInfo {
    /// <p>The Amazon Resource Name (ARN) of the contact channel.</p>
    pub contact_channel_id: ::std::string::String,
    /// <p>The number of minutes to wait to retry sending engagement in the case the engagement initially fails.</p>
    pub retry_interval_in_minutes: ::std::option::Option<i32>,
}
impl ChannelTargetInfo {
    /// <p>The Amazon Resource Name (ARN) of the contact channel.</p>
    pub fn contact_channel_id(&self) -> &str {
        use std::ops::Deref;
        self.contact_channel_id.deref()
    }
    /// <p>The number of minutes to wait to retry sending engagement in the case the engagement initially fails.</p>
    pub fn retry_interval_in_minutes(&self) -> ::std::option::Option<i32> {
        self.retry_interval_in_minutes
    }
}
impl ChannelTargetInfo {
    /// Creates a new builder-style object to manufacture [`ChannelTargetInfo`](crate::types::ChannelTargetInfo).
    pub fn builder() -> crate::types::builders::ChannelTargetInfoBuilder {
        crate::types::builders::ChannelTargetInfoBuilder::default()
    }
}

/// A builder for [`ChannelTargetInfo`](crate::types::ChannelTargetInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ChannelTargetInfoBuilder {
    pub(crate) contact_channel_id: ::std::option::Option<::std::string::String>,
    pub(crate) retry_interval_in_minutes: ::std::option::Option<i32>,
}
impl ChannelTargetInfoBuilder {
    /// <p>The Amazon Resource Name (ARN) of the contact channel.</p>
    /// This field is required.
    pub fn contact_channel_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.contact_channel_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the contact channel.</p>
    pub fn set_contact_channel_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.contact_channel_id = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the contact channel.</p>
    pub fn get_contact_channel_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.contact_channel_id
    }
    /// <p>The number of minutes to wait to retry sending engagement in the case the engagement initially fails.</p>
    pub fn retry_interval_in_minutes(mut self, input: i32) -> Self {
        self.retry_interval_in_minutes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of minutes to wait to retry sending engagement in the case the engagement initially fails.</p>
    pub fn set_retry_interval_in_minutes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.retry_interval_in_minutes = input;
        self
    }
    /// <p>The number of minutes to wait to retry sending engagement in the case the engagement initially fails.</p>
    pub fn get_retry_interval_in_minutes(&self) -> &::std::option::Option<i32> {
        &self.retry_interval_in_minutes
    }
    /// Consumes the builder and constructs a [`ChannelTargetInfo`](crate::types::ChannelTargetInfo).
    /// This method will fail if any of the following fields are not set:
    /// - [`contact_channel_id`](crate::types::builders::ChannelTargetInfoBuilder::contact_channel_id)
    pub fn build(self) -> ::std::result::Result<crate::types::ChannelTargetInfo, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ChannelTargetInfo {
            contact_channel_id: self.contact_channel_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "contact_channel_id",
                    "contact_channel_id was not specified but it is required when building ChannelTargetInfo",
                )
            })?,
            retry_interval_in_minutes: self.retry_interval_in_minutes,
        })
    }
}
