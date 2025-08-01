// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateStreamModeInput {
    /// <p>Specifies the ARN of the data stream whose capacity mode you want to update.</p>
    pub stream_arn: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the capacity mode to which you want to set your data stream. Currently, in Kinesis Data Streams, you can choose between an <b>on-demand</b> capacity mode and a <b>provisioned</b> capacity mode for your data streams.</p>
    pub stream_mode_details: ::std::option::Option<crate::types::StreamModeDetails>,
}
impl UpdateStreamModeInput {
    /// <p>Specifies the ARN of the data stream whose capacity mode you want to update.</p>
    pub fn stream_arn(&self) -> ::std::option::Option<&str> {
        self.stream_arn.as_deref()
    }
    /// <p>Specifies the capacity mode to which you want to set your data stream. Currently, in Kinesis Data Streams, you can choose between an <b>on-demand</b> capacity mode and a <b>provisioned</b> capacity mode for your data streams.</p>
    pub fn stream_mode_details(&self) -> ::std::option::Option<&crate::types::StreamModeDetails> {
        self.stream_mode_details.as_ref()
    }
}
impl UpdateStreamModeInput {
    /// Creates a new builder-style object to manufacture [`UpdateStreamModeInput`](crate::operation::update_stream_mode::UpdateStreamModeInput).
    pub fn builder() -> crate::operation::update_stream_mode::builders::UpdateStreamModeInputBuilder {
        crate::operation::update_stream_mode::builders::UpdateStreamModeInputBuilder::default()
    }
}

/// A builder for [`UpdateStreamModeInput`](crate::operation::update_stream_mode::UpdateStreamModeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateStreamModeInputBuilder {
    pub(crate) stream_arn: ::std::option::Option<::std::string::String>,
    pub(crate) stream_mode_details: ::std::option::Option<crate::types::StreamModeDetails>,
}
impl UpdateStreamModeInputBuilder {
    /// <p>Specifies the ARN of the data stream whose capacity mode you want to update.</p>
    /// This field is required.
    pub fn stream_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the ARN of the data stream whose capacity mode you want to update.</p>
    pub fn set_stream_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_arn = input;
        self
    }
    /// <p>Specifies the ARN of the data stream whose capacity mode you want to update.</p>
    pub fn get_stream_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_arn
    }
    /// <p>Specifies the capacity mode to which you want to set your data stream. Currently, in Kinesis Data Streams, you can choose between an <b>on-demand</b> capacity mode and a <b>provisioned</b> capacity mode for your data streams.</p>
    /// This field is required.
    pub fn stream_mode_details(mut self, input: crate::types::StreamModeDetails) -> Self {
        self.stream_mode_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the capacity mode to which you want to set your data stream. Currently, in Kinesis Data Streams, you can choose between an <b>on-demand</b> capacity mode and a <b>provisioned</b> capacity mode for your data streams.</p>
    pub fn set_stream_mode_details(mut self, input: ::std::option::Option<crate::types::StreamModeDetails>) -> Self {
        self.stream_mode_details = input;
        self
    }
    /// <p>Specifies the capacity mode to which you want to set your data stream. Currently, in Kinesis Data Streams, you can choose between an <b>on-demand</b> capacity mode and a <b>provisioned</b> capacity mode for your data streams.</p>
    pub fn get_stream_mode_details(&self) -> &::std::option::Option<crate::types::StreamModeDetails> {
        &self.stream_mode_details
    }
    /// Consumes the builder and constructs a [`UpdateStreamModeInput`](crate::operation::update_stream_mode::UpdateStreamModeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_stream_mode::UpdateStreamModeInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_stream_mode::UpdateStreamModeInput {
            stream_arn: self.stream_arn,
            stream_mode_details: self.stream_mode_details,
        })
    }
}
