// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetChannelInput {
    /// <p>ARN of the channel for which the configuration is to be retrieved.</p>
    pub arn: ::std::option::Option<::std::string::String>,
}
impl GetChannelInput {
    /// <p>ARN of the channel for which the configuration is to be retrieved.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
}
impl GetChannelInput {
    /// Creates a new builder-style object to manufacture [`GetChannelInput`](crate::operation::get_channel::GetChannelInput).
    pub fn builder() -> crate::operation::get_channel::builders::GetChannelInputBuilder {
        crate::operation::get_channel::builders::GetChannelInputBuilder::default()
    }
}

/// A builder for [`GetChannelInput`](crate::operation::get_channel::GetChannelInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetChannelInputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
}
impl GetChannelInputBuilder {
    /// <p>ARN of the channel for which the configuration is to be retrieved.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ARN of the channel for which the configuration is to be retrieved.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>ARN of the channel for which the configuration is to be retrieved.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// Consumes the builder and constructs a [`GetChannelInput`](crate::operation::get_channel::GetChannelInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_channel::GetChannelInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_channel::GetChannelInput { arn: self.arn })
    }
}
