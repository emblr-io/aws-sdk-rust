// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetStreamInput {
    /// <p>The Amazon Resource Name (ARN) of the stream for which detailed information is requested. This uniquely identifies the specific stream you want to get information about.</p>
    pub stream_arn: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of shard objects to return in a single <code>GetStream</code> request. Default value is 100. The minimum value is 1 and the maximum value is 1000.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Optional filter criteria to apply when retrieving shards. You can filter shards based on their state or other attributes to narrow down the results returned by the <code>GetStream</code> operation.</p>
    pub shard_filter: ::std::option::Option<crate::types::ShardFilter>,
    /// <p>An optional pagination token provided by a previous <code>GetStream</code> operation. If this parameter is specified, the response includes only records beyond the token, up to the value specified by <code>maxResults</code>.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl GetStreamInput {
    /// <p>The Amazon Resource Name (ARN) of the stream for which detailed information is requested. This uniquely identifies the specific stream you want to get information about.</p>
    pub fn stream_arn(&self) -> ::std::option::Option<&str> {
        self.stream_arn.as_deref()
    }
    /// <p>The maximum number of shard objects to return in a single <code>GetStream</code> request. Default value is 100. The minimum value is 1 and the maximum value is 1000.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Optional filter criteria to apply when retrieving shards. You can filter shards based on their state or other attributes to narrow down the results returned by the <code>GetStream</code> operation.</p>
    pub fn shard_filter(&self) -> ::std::option::Option<&crate::types::ShardFilter> {
        self.shard_filter.as_ref()
    }
    /// <p>An optional pagination token provided by a previous <code>GetStream</code> operation. If this parameter is specified, the response includes only records beyond the token, up to the value specified by <code>maxResults</code>.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl GetStreamInput {
    /// Creates a new builder-style object to manufacture [`GetStreamInput`](crate::operation::get_stream::GetStreamInput).
    pub fn builder() -> crate::operation::get_stream::builders::GetStreamInputBuilder {
        crate::operation::get_stream::builders::GetStreamInputBuilder::default()
    }
}

/// A builder for [`GetStreamInput`](crate::operation::get_stream::GetStreamInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetStreamInputBuilder {
    pub(crate) stream_arn: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) shard_filter: ::std::option::Option<crate::types::ShardFilter>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl GetStreamInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the stream for which detailed information is requested. This uniquely identifies the specific stream you want to get information about.</p>
    /// This field is required.
    pub fn stream_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the stream for which detailed information is requested. This uniquely identifies the specific stream you want to get information about.</p>
    pub fn set_stream_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the stream for which detailed information is requested. This uniquely identifies the specific stream you want to get information about.</p>
    pub fn get_stream_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_arn
    }
    /// <p>The maximum number of shard objects to return in a single <code>GetStream</code> request. Default value is 100. The minimum value is 1 and the maximum value is 1000.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of shard objects to return in a single <code>GetStream</code> request. Default value is 100. The minimum value is 1 and the maximum value is 1000.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of shard objects to return in a single <code>GetStream</code> request. Default value is 100. The minimum value is 1 and the maximum value is 1000.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>Optional filter criteria to apply when retrieving shards. You can filter shards based on their state or other attributes to narrow down the results returned by the <code>GetStream</code> operation.</p>
    pub fn shard_filter(mut self, input: crate::types::ShardFilter) -> Self {
        self.shard_filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>Optional filter criteria to apply when retrieving shards. You can filter shards based on their state or other attributes to narrow down the results returned by the <code>GetStream</code> operation.</p>
    pub fn set_shard_filter(mut self, input: ::std::option::Option<crate::types::ShardFilter>) -> Self {
        self.shard_filter = input;
        self
    }
    /// <p>Optional filter criteria to apply when retrieving shards. You can filter shards based on their state or other attributes to narrow down the results returned by the <code>GetStream</code> operation.</p>
    pub fn get_shard_filter(&self) -> &::std::option::Option<crate::types::ShardFilter> {
        &self.shard_filter
    }
    /// <p>An optional pagination token provided by a previous <code>GetStream</code> operation. If this parameter is specified, the response includes only records beyond the token, up to the value specified by <code>maxResults</code>.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional pagination token provided by a previous <code>GetStream</code> operation. If this parameter is specified, the response includes only records beyond the token, up to the value specified by <code>maxResults</code>.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>An optional pagination token provided by a previous <code>GetStream</code> operation. If this parameter is specified, the response includes only records beyond the token, up to the value specified by <code>maxResults</code>.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`GetStreamInput`](crate::operation::get_stream::GetStreamInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_stream::GetStreamInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_stream::GetStreamInput {
            stream_arn: self.stream_arn,
            max_results: self.max_results,
            shard_filter: self.shard_filter,
            next_token: self.next_token,
        })
    }
}
