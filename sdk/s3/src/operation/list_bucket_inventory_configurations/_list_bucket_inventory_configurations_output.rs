// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListBucketInventoryConfigurationsOutput {
    /// <p>If sent in the request, the marker that is used as a starting point for this inventory configuration list response.</p>
    pub continuation_token: ::std::option::Option<::std::string::String>,
    /// <p>The list of inventory configurations for a bucket.</p>
    pub inventory_configuration_list: ::std::option::Option<::std::vec::Vec<crate::types::InventoryConfiguration>>,
    /// <p>Tells whether the returned list of inventory configurations is complete. A value of true indicates that the list is not complete and the NextContinuationToken is provided for a subsequent request.</p>
    pub is_truncated: ::std::option::Option<bool>,
    /// <p>The marker used to continue this inventory configuration listing. Use the <code>NextContinuationToken</code> from this response to continue the listing in a subsequent request. The continuation token is an opaque value that Amazon S3 understands.</p>
    pub next_continuation_token: ::std::option::Option<::std::string::String>,
    _extended_request_id: Option<String>,
    _request_id: Option<String>,
}
impl ListBucketInventoryConfigurationsOutput {
    /// <p>If sent in the request, the marker that is used as a starting point for this inventory configuration list response.</p>
    pub fn continuation_token(&self) -> ::std::option::Option<&str> {
        self.continuation_token.as_deref()
    }
    /// <p>The list of inventory configurations for a bucket.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.inventory_configuration_list.is_none()`.
    pub fn inventory_configuration_list(&self) -> &[crate::types::InventoryConfiguration] {
        self.inventory_configuration_list.as_deref().unwrap_or_default()
    }
    /// <p>Tells whether the returned list of inventory configurations is complete. A value of true indicates that the list is not complete and the NextContinuationToken is provided for a subsequent request.</p>
    pub fn is_truncated(&self) -> ::std::option::Option<bool> {
        self.is_truncated
    }
    /// <p>The marker used to continue this inventory configuration listing. Use the <code>NextContinuationToken</code> from this response to continue the listing in a subsequent request. The continuation token is an opaque value that Amazon S3 understands.</p>
    pub fn next_continuation_token(&self) -> ::std::option::Option<&str> {
        self.next_continuation_token.as_deref()
    }
}
impl crate::s3_request_id::RequestIdExt for ListBucketInventoryConfigurationsOutput {
    fn extended_request_id(&self) -> Option<&str> {
        self._extended_request_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListBucketInventoryConfigurationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListBucketInventoryConfigurationsOutput {
    /// Creates a new builder-style object to manufacture [`ListBucketInventoryConfigurationsOutput`](crate::operation::list_bucket_inventory_configurations::ListBucketInventoryConfigurationsOutput).
    pub fn builder() -> crate::operation::list_bucket_inventory_configurations::builders::ListBucketInventoryConfigurationsOutputBuilder {
        crate::operation::list_bucket_inventory_configurations::builders::ListBucketInventoryConfigurationsOutputBuilder::default()
    }
}

/// A builder for [`ListBucketInventoryConfigurationsOutput`](crate::operation::list_bucket_inventory_configurations::ListBucketInventoryConfigurationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListBucketInventoryConfigurationsOutputBuilder {
    pub(crate) continuation_token: ::std::option::Option<::std::string::String>,
    pub(crate) inventory_configuration_list: ::std::option::Option<::std::vec::Vec<crate::types::InventoryConfiguration>>,
    pub(crate) is_truncated: ::std::option::Option<bool>,
    pub(crate) next_continuation_token: ::std::option::Option<::std::string::String>,
    _extended_request_id: Option<String>,
    _request_id: Option<String>,
}
impl ListBucketInventoryConfigurationsOutputBuilder {
    /// <p>If sent in the request, the marker that is used as a starting point for this inventory configuration list response.</p>
    pub fn continuation_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.continuation_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If sent in the request, the marker that is used as a starting point for this inventory configuration list response.</p>
    pub fn set_continuation_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.continuation_token = input;
        self
    }
    /// <p>If sent in the request, the marker that is used as a starting point for this inventory configuration list response.</p>
    pub fn get_continuation_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.continuation_token
    }
    /// Appends an item to `inventory_configuration_list`.
    ///
    /// To override the contents of this collection use [`set_inventory_configuration_list`](Self::set_inventory_configuration_list).
    ///
    /// <p>The list of inventory configurations for a bucket.</p>
    pub fn inventory_configuration_list(mut self, input: crate::types::InventoryConfiguration) -> Self {
        let mut v = self.inventory_configuration_list.unwrap_or_default();
        v.push(input);
        self.inventory_configuration_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of inventory configurations for a bucket.</p>
    pub fn set_inventory_configuration_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InventoryConfiguration>>) -> Self {
        self.inventory_configuration_list = input;
        self
    }
    /// <p>The list of inventory configurations for a bucket.</p>
    pub fn get_inventory_configuration_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InventoryConfiguration>> {
        &self.inventory_configuration_list
    }
    /// <p>Tells whether the returned list of inventory configurations is complete. A value of true indicates that the list is not complete and the NextContinuationToken is provided for a subsequent request.</p>
    pub fn is_truncated(mut self, input: bool) -> Self {
        self.is_truncated = ::std::option::Option::Some(input);
        self
    }
    /// <p>Tells whether the returned list of inventory configurations is complete. A value of true indicates that the list is not complete and the NextContinuationToken is provided for a subsequent request.</p>
    pub fn set_is_truncated(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_truncated = input;
        self
    }
    /// <p>Tells whether the returned list of inventory configurations is complete. A value of true indicates that the list is not complete and the NextContinuationToken is provided for a subsequent request.</p>
    pub fn get_is_truncated(&self) -> &::std::option::Option<bool> {
        &self.is_truncated
    }
    /// <p>The marker used to continue this inventory configuration listing. Use the <code>NextContinuationToken</code> from this response to continue the listing in a subsequent request. The continuation token is an opaque value that Amazon S3 understands.</p>
    pub fn next_continuation_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_continuation_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The marker used to continue this inventory configuration listing. Use the <code>NextContinuationToken</code> from this response to continue the listing in a subsequent request. The continuation token is an opaque value that Amazon S3 understands.</p>
    pub fn set_next_continuation_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_continuation_token = input;
        self
    }
    /// <p>The marker used to continue this inventory configuration listing. Use the <code>NextContinuationToken</code> from this response to continue the listing in a subsequent request. The continuation token is an opaque value that Amazon S3 understands.</p>
    pub fn get_next_continuation_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_continuation_token
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
    /// Consumes the builder and constructs a [`ListBucketInventoryConfigurationsOutput`](crate::operation::list_bucket_inventory_configurations::ListBucketInventoryConfigurationsOutput).
    pub fn build(self) -> crate::operation::list_bucket_inventory_configurations::ListBucketInventoryConfigurationsOutput {
        crate::operation::list_bucket_inventory_configurations::ListBucketInventoryConfigurationsOutput {
            continuation_token: self.continuation_token,
            inventory_configuration_list: self.inventory_configuration_list,
            is_truncated: self.is_truncated,
            next_continuation_token: self.next_continuation_token,
            _extended_request_id: self._extended_request_id,
            _request_id: self._request_id,
        }
    }
}
