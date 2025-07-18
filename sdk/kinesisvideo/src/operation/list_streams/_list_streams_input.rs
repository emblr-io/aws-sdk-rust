// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListStreamsInput {
    /// <p>The maximum number of streams to return in the response. The default is 10,000.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>If you specify this parameter, when the result of a <code>ListStreams</code> operation is truncated, the call returns the <code>NextToken</code> in the response. To get another batch of streams, provide this token in your next request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Optional: Returns only streams that satisfy a specific condition. Currently, you can specify only the prefix of a stream name as a condition.</p>
    pub stream_name_condition: ::std::option::Option<crate::types::StreamNameCondition>,
}
impl ListStreamsInput {
    /// <p>The maximum number of streams to return in the response. The default is 10,000.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>If you specify this parameter, when the result of a <code>ListStreams</code> operation is truncated, the call returns the <code>NextToken</code> in the response. To get another batch of streams, provide this token in your next request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Optional: Returns only streams that satisfy a specific condition. Currently, you can specify only the prefix of a stream name as a condition.</p>
    pub fn stream_name_condition(&self) -> ::std::option::Option<&crate::types::StreamNameCondition> {
        self.stream_name_condition.as_ref()
    }
}
impl ListStreamsInput {
    /// Creates a new builder-style object to manufacture [`ListStreamsInput`](crate::operation::list_streams::ListStreamsInput).
    pub fn builder() -> crate::operation::list_streams::builders::ListStreamsInputBuilder {
        crate::operation::list_streams::builders::ListStreamsInputBuilder::default()
    }
}

/// A builder for [`ListStreamsInput`](crate::operation::list_streams::ListStreamsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListStreamsInputBuilder {
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) stream_name_condition: ::std::option::Option<crate::types::StreamNameCondition>,
}
impl ListStreamsInputBuilder {
    /// <p>The maximum number of streams to return in the response. The default is 10,000.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of streams to return in the response. The default is 10,000.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of streams to return in the response. The default is 10,000.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>If you specify this parameter, when the result of a <code>ListStreams</code> operation is truncated, the call returns the <code>NextToken</code> in the response. To get another batch of streams, provide this token in your next request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If you specify this parameter, when the result of a <code>ListStreams</code> operation is truncated, the call returns the <code>NextToken</code> in the response. To get another batch of streams, provide this token in your next request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If you specify this parameter, when the result of a <code>ListStreams</code> operation is truncated, the call returns the <code>NextToken</code> in the response. To get another batch of streams, provide this token in your next request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Optional: Returns only streams that satisfy a specific condition. Currently, you can specify only the prefix of a stream name as a condition.</p>
    pub fn stream_name_condition(mut self, input: crate::types::StreamNameCondition) -> Self {
        self.stream_name_condition = ::std::option::Option::Some(input);
        self
    }
    /// <p>Optional: Returns only streams that satisfy a specific condition. Currently, you can specify only the prefix of a stream name as a condition.</p>
    pub fn set_stream_name_condition(mut self, input: ::std::option::Option<crate::types::StreamNameCondition>) -> Self {
        self.stream_name_condition = input;
        self
    }
    /// <p>Optional: Returns only streams that satisfy a specific condition. Currently, you can specify only the prefix of a stream name as a condition.</p>
    pub fn get_stream_name_condition(&self) -> &::std::option::Option<crate::types::StreamNameCondition> {
        &self.stream_name_condition
    }
    /// Consumes the builder and constructs a [`ListStreamsInput`](crate::operation::list_streams::ListStreamsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_streams::ListStreamsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_streams::ListStreamsInput {
            max_results: self.max_results,
            next_token: self.next_token,
            stream_name_condition: self.stream_name_condition,
        })
    }
}
