// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeStreamSummaryInput {
    /// <p>The name of the stream to describe.</p>
    pub stream_name: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the stream.</p>
    pub stream_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeStreamSummaryInput {
    /// <p>The name of the stream to describe.</p>
    pub fn stream_name(&self) -> ::std::option::Option<&str> {
        self.stream_name.as_deref()
    }
    /// <p>The ARN of the stream.</p>
    pub fn stream_arn(&self) -> ::std::option::Option<&str> {
        self.stream_arn.as_deref()
    }
}
impl DescribeStreamSummaryInput {
    /// Creates a new builder-style object to manufacture [`DescribeStreamSummaryInput`](crate::operation::describe_stream_summary::DescribeStreamSummaryInput).
    pub fn builder() -> crate::operation::describe_stream_summary::builders::DescribeStreamSummaryInputBuilder {
        crate::operation::describe_stream_summary::builders::DescribeStreamSummaryInputBuilder::default()
    }
}

/// A builder for [`DescribeStreamSummaryInput`](crate::operation::describe_stream_summary::DescribeStreamSummaryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeStreamSummaryInputBuilder {
    pub(crate) stream_name: ::std::option::Option<::std::string::String>,
    pub(crate) stream_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeStreamSummaryInputBuilder {
    /// <p>The name of the stream to describe.</p>
    pub fn stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the stream to describe.</p>
    pub fn set_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_name = input;
        self
    }
    /// <p>The name of the stream to describe.</p>
    pub fn get_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_name
    }
    /// <p>The ARN of the stream.</p>
    pub fn stream_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the stream.</p>
    pub fn set_stream_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_arn = input;
        self
    }
    /// <p>The ARN of the stream.</p>
    pub fn get_stream_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_arn
    }
    /// Consumes the builder and constructs a [`DescribeStreamSummaryInput`](crate::operation::describe_stream_summary::DescribeStreamSummaryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_stream_summary::DescribeStreamSummaryInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_stream_summary::DescribeStreamSummaryInput {
            stream_name: self.stream_name,
            stream_arn: self.stream_arn,
        })
    }
}
