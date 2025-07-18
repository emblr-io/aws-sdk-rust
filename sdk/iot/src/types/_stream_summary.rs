// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A summary of a stream.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StreamSummary {
    /// <p>The stream ID.</p>
    pub stream_id: ::std::option::Option<::std::string::String>,
    /// <p>The stream ARN.</p>
    pub stream_arn: ::std::option::Option<::std::string::String>,
    /// <p>The stream version.</p>
    pub stream_version: ::std::option::Option<i32>,
    /// <p>A description of the stream.</p>
    pub description: ::std::option::Option<::std::string::String>,
}
impl StreamSummary {
    /// <p>The stream ID.</p>
    pub fn stream_id(&self) -> ::std::option::Option<&str> {
        self.stream_id.as_deref()
    }
    /// <p>The stream ARN.</p>
    pub fn stream_arn(&self) -> ::std::option::Option<&str> {
        self.stream_arn.as_deref()
    }
    /// <p>The stream version.</p>
    pub fn stream_version(&self) -> ::std::option::Option<i32> {
        self.stream_version
    }
    /// <p>A description of the stream.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl StreamSummary {
    /// Creates a new builder-style object to manufacture [`StreamSummary`](crate::types::StreamSummary).
    pub fn builder() -> crate::types::builders::StreamSummaryBuilder {
        crate::types::builders::StreamSummaryBuilder::default()
    }
}

/// A builder for [`StreamSummary`](crate::types::StreamSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StreamSummaryBuilder {
    pub(crate) stream_id: ::std::option::Option<::std::string::String>,
    pub(crate) stream_arn: ::std::option::Option<::std::string::String>,
    pub(crate) stream_version: ::std::option::Option<i32>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl StreamSummaryBuilder {
    /// <p>The stream ID.</p>
    pub fn stream_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The stream ID.</p>
    pub fn set_stream_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_id = input;
        self
    }
    /// <p>The stream ID.</p>
    pub fn get_stream_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_id
    }
    /// <p>The stream ARN.</p>
    pub fn stream_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The stream ARN.</p>
    pub fn set_stream_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_arn = input;
        self
    }
    /// <p>The stream ARN.</p>
    pub fn get_stream_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_arn
    }
    /// <p>The stream version.</p>
    pub fn stream_version(mut self, input: i32) -> Self {
        self.stream_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The stream version.</p>
    pub fn set_stream_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.stream_version = input;
        self
    }
    /// <p>The stream version.</p>
    pub fn get_stream_version(&self) -> &::std::option::Option<i32> {
        &self.stream_version
    }
    /// <p>A description of the stream.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the stream.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the stream.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`StreamSummary`](crate::types::StreamSummary).
    pub fn build(self) -> crate::types::StreamSummary {
        crate::types::StreamSummary {
            stream_id: self.stream_id,
            stream_arn: self.stream_arn,
            stream_version: self.stream_version,
            description: self.description,
        }
    }
}
