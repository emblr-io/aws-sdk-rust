// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListBucketsOutput {
    /// <p>The list of buckets owned by the requester.</p>
    pub buckets: ::std::option::Option<::std::vec::Vec<crate::types::Bucket>>,
    /// <p>The owner of the buckets listed.</p>
    pub owner: ::std::option::Option<crate::types::Owner>,
    /// <p><code>ContinuationToken</code> is included in the response when there are more buckets that can be listed with pagination. The next <code>ListBuckets</code> request to Amazon S3 can be continued with this <code>ContinuationToken</code>. <code>ContinuationToken</code> is obfuscated and is not a real bucket.</p>
    pub continuation_token: ::std::option::Option<::std::string::String>,
    /// <p>If <code>Prefix</code> was sent with the request, it is included in the response.</p>
    /// <p>All bucket names in the response begin with the specified bucket name prefix.</p>
    pub prefix: ::std::option::Option<::std::string::String>,
    _extended_request_id: Option<String>,
    _request_id: Option<String>,
}
impl ListBucketsOutput {
    /// <p>The list of buckets owned by the requester.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.buckets.is_none()`.
    pub fn buckets(&self) -> &[crate::types::Bucket] {
        self.buckets.as_deref().unwrap_or_default()
    }
    /// <p>The owner of the buckets listed.</p>
    pub fn owner(&self) -> ::std::option::Option<&crate::types::Owner> {
        self.owner.as_ref()
    }
    /// <p><code>ContinuationToken</code> is included in the response when there are more buckets that can be listed with pagination. The next <code>ListBuckets</code> request to Amazon S3 can be continued with this <code>ContinuationToken</code>. <code>ContinuationToken</code> is obfuscated and is not a real bucket.</p>
    pub fn continuation_token(&self) -> ::std::option::Option<&str> {
        self.continuation_token.as_deref()
    }
    /// <p>If <code>Prefix</code> was sent with the request, it is included in the response.</p>
    /// <p>All bucket names in the response begin with the specified bucket name prefix.</p>
    pub fn prefix(&self) -> ::std::option::Option<&str> {
        self.prefix.as_deref()
    }
}
impl crate::s3_request_id::RequestIdExt for ListBucketsOutput {
    fn extended_request_id(&self) -> Option<&str> {
        self._extended_request_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListBucketsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListBucketsOutput {
    /// Creates a new builder-style object to manufacture [`ListBucketsOutput`](crate::operation::list_buckets::ListBucketsOutput).
    pub fn builder() -> crate::operation::list_buckets::builders::ListBucketsOutputBuilder {
        crate::operation::list_buckets::builders::ListBucketsOutputBuilder::default()
    }
}

/// A builder for [`ListBucketsOutput`](crate::operation::list_buckets::ListBucketsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListBucketsOutputBuilder {
    pub(crate) buckets: ::std::option::Option<::std::vec::Vec<crate::types::Bucket>>,
    pub(crate) owner: ::std::option::Option<crate::types::Owner>,
    pub(crate) continuation_token: ::std::option::Option<::std::string::String>,
    pub(crate) prefix: ::std::option::Option<::std::string::String>,
    _extended_request_id: Option<String>,
    _request_id: Option<String>,
}
impl ListBucketsOutputBuilder {
    /// Appends an item to `buckets`.
    ///
    /// To override the contents of this collection use [`set_buckets`](Self::set_buckets).
    ///
    /// <p>The list of buckets owned by the requester.</p>
    pub fn buckets(mut self, input: crate::types::Bucket) -> Self {
        let mut v = self.buckets.unwrap_or_default();
        v.push(input);
        self.buckets = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of buckets owned by the requester.</p>
    pub fn set_buckets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Bucket>>) -> Self {
        self.buckets = input;
        self
    }
    /// <p>The list of buckets owned by the requester.</p>
    pub fn get_buckets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Bucket>> {
        &self.buckets
    }
    /// <p>The owner of the buckets listed.</p>
    pub fn owner(mut self, input: crate::types::Owner) -> Self {
        self.owner = ::std::option::Option::Some(input);
        self
    }
    /// <p>The owner of the buckets listed.</p>
    pub fn set_owner(mut self, input: ::std::option::Option<crate::types::Owner>) -> Self {
        self.owner = input;
        self
    }
    /// <p>The owner of the buckets listed.</p>
    pub fn get_owner(&self) -> &::std::option::Option<crate::types::Owner> {
        &self.owner
    }
    /// <p><code>ContinuationToken</code> is included in the response when there are more buckets that can be listed with pagination. The next <code>ListBuckets</code> request to Amazon S3 can be continued with this <code>ContinuationToken</code>. <code>ContinuationToken</code> is obfuscated and is not a real bucket.</p>
    pub fn continuation_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.continuation_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p><code>ContinuationToken</code> is included in the response when there are more buckets that can be listed with pagination. The next <code>ListBuckets</code> request to Amazon S3 can be continued with this <code>ContinuationToken</code>. <code>ContinuationToken</code> is obfuscated and is not a real bucket.</p>
    pub fn set_continuation_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.continuation_token = input;
        self
    }
    /// <p><code>ContinuationToken</code> is included in the response when there are more buckets that can be listed with pagination. The next <code>ListBuckets</code> request to Amazon S3 can be continued with this <code>ContinuationToken</code>. <code>ContinuationToken</code> is obfuscated and is not a real bucket.</p>
    pub fn get_continuation_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.continuation_token
    }
    /// <p>If <code>Prefix</code> was sent with the request, it is included in the response.</p>
    /// <p>All bucket names in the response begin with the specified bucket name prefix.</p>
    pub fn prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If <code>Prefix</code> was sent with the request, it is included in the response.</p>
    /// <p>All bucket names in the response begin with the specified bucket name prefix.</p>
    pub fn set_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix = input;
        self
    }
    /// <p>If <code>Prefix</code> was sent with the request, it is included in the response.</p>
    /// <p>All bucket names in the response begin with the specified bucket name prefix.</p>
    pub fn get_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix
    }
    pub(crate) fn _extended_request_id(mut self, extended_request_id: impl Into<String>) -> Self {
        self._extended_request_id = Some(extended_request_id.into());
        self
    }

    pub(crate) fn _set_extended_request_id(&mut self, extended_request_id: Option<String>) -> &mut Self {
        self._extended_request_id = extended_request_id;
        self
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListBucketsOutput`](crate::operation::list_buckets::ListBucketsOutput).
    pub fn build(self) -> crate::operation::list_buckets::ListBucketsOutput {
        crate::operation::list_buckets::ListBucketsOutput {
            buckets: self.buckets,
            owner: self.owner,
            continuation_token: self.continuation_token,
            prefix: self.prefix,
            _extended_request_id: self._extended_request_id,
            _request_id: self._request_id,
        }
    }
}
