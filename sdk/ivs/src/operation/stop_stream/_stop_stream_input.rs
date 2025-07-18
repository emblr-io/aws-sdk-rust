// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopStreamInput {
    /// <p>ARN of the channel for which the stream is to be stopped.</p>
    pub channel_arn: ::std::option::Option<::std::string::String>,
}
impl StopStreamInput {
    /// <p>ARN of the channel for which the stream is to be stopped.</p>
    pub fn channel_arn(&self) -> ::std::option::Option<&str> {
        self.channel_arn.as_deref()
    }
}
impl StopStreamInput {
    /// Creates a new builder-style object to manufacture [`StopStreamInput`](crate::operation::stop_stream::StopStreamInput).
    pub fn builder() -> crate::operation::stop_stream::builders::StopStreamInputBuilder {
        crate::operation::stop_stream::builders::StopStreamInputBuilder::default()
    }
}

/// A builder for [`StopStreamInput`](crate::operation::stop_stream::StopStreamInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopStreamInputBuilder {
    pub(crate) channel_arn: ::std::option::Option<::std::string::String>,
}
impl StopStreamInputBuilder {
    /// <p>ARN of the channel for which the stream is to be stopped.</p>
    /// This field is required.
    pub fn channel_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ARN of the channel for which the stream is to be stopped.</p>
    pub fn set_channel_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_arn = input;
        self
    }
    /// <p>ARN of the channel for which the stream is to be stopped.</p>
    pub fn get_channel_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_arn
    }
    /// Consumes the builder and constructs a [`StopStreamInput`](crate::operation::stop_stream::StopStreamInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::stop_stream::StopStreamInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::stop_stream::StopStreamInput {
            channel_arn: self.channel_arn,
        })
    }
}
