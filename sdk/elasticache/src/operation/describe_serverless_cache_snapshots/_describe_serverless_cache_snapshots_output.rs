// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeServerlessCacheSnapshotsOutput {
    /// <p>An optional marker returned from a prior request to support pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by max-results. Available for Valkey, Redis OSS and Serverless Memcached only.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The serverless caches snapshots associated with a given description request. Available for Valkey, Redis OSS and Serverless Memcached only.</p>
    pub serverless_cache_snapshots: ::std::option::Option<::std::vec::Vec<crate::types::ServerlessCacheSnapshot>>,
    _request_id: Option<String>,
}
impl DescribeServerlessCacheSnapshotsOutput {
    /// <p>An optional marker returned from a prior request to support pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by max-results. Available for Valkey, Redis OSS and Serverless Memcached only.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The serverless caches snapshots associated with a given description request. Available for Valkey, Redis OSS and Serverless Memcached only.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.serverless_cache_snapshots.is_none()`.
    pub fn serverless_cache_snapshots(&self) -> &[crate::types::ServerlessCacheSnapshot] {
        self.serverless_cache_snapshots.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeServerlessCacheSnapshotsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeServerlessCacheSnapshotsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeServerlessCacheSnapshotsOutput`](crate::operation::describe_serverless_cache_snapshots::DescribeServerlessCacheSnapshotsOutput).
    pub fn builder() -> crate::operation::describe_serverless_cache_snapshots::builders::DescribeServerlessCacheSnapshotsOutputBuilder {
        crate::operation::describe_serverless_cache_snapshots::builders::DescribeServerlessCacheSnapshotsOutputBuilder::default()
    }
}

/// A builder for [`DescribeServerlessCacheSnapshotsOutput`](crate::operation::describe_serverless_cache_snapshots::DescribeServerlessCacheSnapshotsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeServerlessCacheSnapshotsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) serverless_cache_snapshots: ::std::option::Option<::std::vec::Vec<crate::types::ServerlessCacheSnapshot>>,
    _request_id: Option<String>,
}
impl DescribeServerlessCacheSnapshotsOutputBuilder {
    /// <p>An optional marker returned from a prior request to support pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by max-results. Available for Valkey, Redis OSS and Serverless Memcached only.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional marker returned from a prior request to support pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by max-results. Available for Valkey, Redis OSS and Serverless Memcached only.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>An optional marker returned from a prior request to support pagination of results from this operation. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by max-results. Available for Valkey, Redis OSS and Serverless Memcached only.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `serverless_cache_snapshots`.
    ///
    /// To override the contents of this collection use [`set_serverless_cache_snapshots`](Self::set_serverless_cache_snapshots).
    ///
    /// <p>The serverless caches snapshots associated with a given description request. Available for Valkey, Redis OSS and Serverless Memcached only.</p>
    pub fn serverless_cache_snapshots(mut self, input: crate::types::ServerlessCacheSnapshot) -> Self {
        let mut v = self.serverless_cache_snapshots.unwrap_or_default();
        v.push(input);
        self.serverless_cache_snapshots = ::std::option::Option::Some(v);
        self
    }
    /// <p>The serverless caches snapshots associated with a given description request. Available for Valkey, Redis OSS and Serverless Memcached only.</p>
    pub fn set_serverless_cache_snapshots(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ServerlessCacheSnapshot>>) -> Self {
        self.serverless_cache_snapshots = input;
        self
    }
    /// <p>The serverless caches snapshots associated with a given description request. Available for Valkey, Redis OSS and Serverless Memcached only.</p>
    pub fn get_serverless_cache_snapshots(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ServerlessCacheSnapshot>> {
        &self.serverless_cache_snapshots
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeServerlessCacheSnapshotsOutput`](crate::operation::describe_serverless_cache_snapshots::DescribeServerlessCacheSnapshotsOutput).
    pub fn build(self) -> crate::operation::describe_serverless_cache_snapshots::DescribeServerlessCacheSnapshotsOutput {
        crate::operation::describe_serverless_cache_snapshots::DescribeServerlessCacheSnapshotsOutput {
            next_token: self.next_token,
            serverless_cache_snapshots: self.serverless_cache_snapshots,
            _request_id: self._request_id,
        }
    }
}
