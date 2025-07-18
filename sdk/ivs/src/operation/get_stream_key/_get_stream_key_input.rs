// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetStreamKeyInput {
    /// <p>ARN for the stream key to be retrieved.</p>
    pub arn: ::std::option::Option<::std::string::String>,
}
impl GetStreamKeyInput {
    /// <p>ARN for the stream key to be retrieved.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
}
impl GetStreamKeyInput {
    /// Creates a new builder-style object to manufacture [`GetStreamKeyInput`](crate::operation::get_stream_key::GetStreamKeyInput).
    pub fn builder() -> crate::operation::get_stream_key::builders::GetStreamKeyInputBuilder {
        crate::operation::get_stream_key::builders::GetStreamKeyInputBuilder::default()
    }
}

/// A builder for [`GetStreamKeyInput`](crate::operation::get_stream_key::GetStreamKeyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetStreamKeyInputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
}
impl GetStreamKeyInputBuilder {
    /// <p>ARN for the stream key to be retrieved.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ARN for the stream key to be retrieved.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>ARN for the stream key to be retrieved.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// Consumes the builder and constructs a [`GetStreamKeyInput`](crate::operation::get_stream_key::GetStreamKeyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_stream_key::GetStreamKeyInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_stream_key::GetStreamKeyInput { arn: self.arn })
    }
}
