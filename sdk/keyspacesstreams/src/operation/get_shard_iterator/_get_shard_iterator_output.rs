// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetShardIteratorOutput {
    /// <p>The unique identifier for the shard iterator. This value is used in the <code>GetRecords</code> operation to retrieve data records from the specified shard. Each shard iterator expires 5 minutes after it is returned to the requester.</p>
    pub shard_iterator: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetShardIteratorOutput {
    /// <p>The unique identifier for the shard iterator. This value is used in the <code>GetRecords</code> operation to retrieve data records from the specified shard. Each shard iterator expires 5 minutes after it is returned to the requester.</p>
    pub fn shard_iterator(&self) -> ::std::option::Option<&str> {
        self.shard_iterator.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetShardIteratorOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetShardIteratorOutput {
    /// Creates a new builder-style object to manufacture [`GetShardIteratorOutput`](crate::operation::get_shard_iterator::GetShardIteratorOutput).
    pub fn builder() -> crate::operation::get_shard_iterator::builders::GetShardIteratorOutputBuilder {
        crate::operation::get_shard_iterator::builders::GetShardIteratorOutputBuilder::default()
    }
}

/// A builder for [`GetShardIteratorOutput`](crate::operation::get_shard_iterator::GetShardIteratorOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetShardIteratorOutputBuilder {
    pub(crate) shard_iterator: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetShardIteratorOutputBuilder {
    /// <p>The unique identifier for the shard iterator. This value is used in the <code>GetRecords</code> operation to retrieve data records from the specified shard. Each shard iterator expires 5 minutes after it is returned to the requester.</p>
    pub fn shard_iterator(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.shard_iterator = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the shard iterator. This value is used in the <code>GetRecords</code> operation to retrieve data records from the specified shard. Each shard iterator expires 5 minutes after it is returned to the requester.</p>
    pub fn set_shard_iterator(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.shard_iterator = input;
        self
    }
    /// <p>The unique identifier for the shard iterator. This value is used in the <code>GetRecords</code> operation to retrieve data records from the specified shard. Each shard iterator expires 5 minutes after it is returned to the requester.</p>
    pub fn get_shard_iterator(&self) -> &::std::option::Option<::std::string::String> {
        &self.shard_iterator
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetShardIteratorOutput`](crate::operation::get_shard_iterator::GetShardIteratorOutput).
    pub fn build(self) -> crate::operation::get_shard_iterator::GetShardIteratorOutput {
        crate::operation::get_shard_iterator::GetShardIteratorOutput {
            shard_iterator: self.shard_iterator,
            _request_id: self._request_id,
        }
    }
}
