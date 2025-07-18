// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetObjectAclOutput {
    /// <p>Container for the bucket owner's display name and ID.</p>
    pub owner: ::std::option::Option<crate::types::Owner>,
    /// <p>A list of grants.</p>
    pub grants: ::std::option::Option<::std::vec::Vec<crate::types::Grant>>,
    /// <p>If present, indicates that the requester was successfully charged for the request. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/RequesterPaysBuckets.html">Using Requester Pays buckets for storage transfers and usage</a> in the <i>Amazon Simple Storage Service user guide</i>.</p><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub request_charged: ::std::option::Option<crate::types::RequestCharged>,
    _extended_request_id: Option<String>,
    _request_id: Option<String>,
}
impl GetObjectAclOutput {
    /// <p>Container for the bucket owner's display name and ID.</p>
    pub fn owner(&self) -> ::std::option::Option<&crate::types::Owner> {
        self.owner.as_ref()
    }
    /// <p>A list of grants.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.grants.is_none()`.
    pub fn grants(&self) -> &[crate::types::Grant] {
        self.grants.as_deref().unwrap_or_default()
    }
    /// <p>If present, indicates that the requester was successfully charged for the request. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/RequesterPaysBuckets.html">Using Requester Pays buckets for storage transfers and usage</a> in the <i>Amazon Simple Storage Service user guide</i>.</p><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn request_charged(&self) -> ::std::option::Option<&crate::types::RequestCharged> {
        self.request_charged.as_ref()
    }
}
impl crate::s3_request_id::RequestIdExt for GetObjectAclOutput {
    fn extended_request_id(&self) -> Option<&str> {
        self._extended_request_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetObjectAclOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetObjectAclOutput {
    /// Creates a new builder-style object to manufacture [`GetObjectAclOutput`](crate::operation::get_object_acl::GetObjectAclOutput).
    pub fn builder() -> crate::operation::get_object_acl::builders::GetObjectAclOutputBuilder {
        crate::operation::get_object_acl::builders::GetObjectAclOutputBuilder::default()
    }
}

/// A builder for [`GetObjectAclOutput`](crate::operation::get_object_acl::GetObjectAclOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetObjectAclOutputBuilder {
    pub(crate) owner: ::std::option::Option<crate::types::Owner>,
    pub(crate) grants: ::std::option::Option<::std::vec::Vec<crate::types::Grant>>,
    pub(crate) request_charged: ::std::option::Option<crate::types::RequestCharged>,
    _extended_request_id: Option<String>,
    _request_id: Option<String>,
}
impl GetObjectAclOutputBuilder {
    /// <p>Container for the bucket owner's display name and ID.</p>
    pub fn owner(mut self, input: crate::types::Owner) -> Self {
        self.owner = ::std::option::Option::Some(input);
        self
    }
    /// <p>Container for the bucket owner's display name and ID.</p>
    pub fn set_owner(mut self, input: ::std::option::Option<crate::types::Owner>) -> Self {
        self.owner = input;
        self
    }
    /// <p>Container for the bucket owner's display name and ID.</p>
    pub fn get_owner(&self) -> &::std::option::Option<crate::types::Owner> {
        &self.owner
    }
    /// Appends an item to `grants`.
    ///
    /// To override the contents of this collection use [`set_grants`](Self::set_grants).
    ///
    /// <p>A list of grants.</p>
    pub fn grants(mut self, input: crate::types::Grant) -> Self {
        let mut v = self.grants.unwrap_or_default();
        v.push(input);
        self.grants = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of grants.</p>
    pub fn set_grants(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Grant>>) -> Self {
        self.grants = input;
        self
    }
    /// <p>A list of grants.</p>
    pub fn get_grants(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Grant>> {
        &self.grants
    }
    /// <p>If present, indicates that the requester was successfully charged for the request. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/RequesterPaysBuckets.html">Using Requester Pays buckets for storage transfers and usage</a> in the <i>Amazon Simple Storage Service user guide</i>.</p><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn request_charged(mut self, input: crate::types::RequestCharged) -> Self {
        self.request_charged = ::std::option::Option::Some(input);
        self
    }
    /// <p>If present, indicates that the requester was successfully charged for the request. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/RequesterPaysBuckets.html">Using Requester Pays buckets for storage transfers and usage</a> in the <i>Amazon Simple Storage Service user guide</i>.</p><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn set_request_charged(mut self, input: ::std::option::Option<crate::types::RequestCharged>) -> Self {
        self.request_charged = input;
        self
    }
    /// <p>If present, indicates that the requester was successfully charged for the request. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/RequesterPaysBuckets.html">Using Requester Pays buckets for storage transfers and usage</a> in the <i>Amazon Simple Storage Service user guide</i>.</p><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn get_request_charged(&self) -> &::std::option::Option<crate::types::RequestCharged> {
        &self.request_charged
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
    /// Consumes the builder and constructs a [`GetObjectAclOutput`](crate::operation::get_object_acl::GetObjectAclOutput).
    pub fn build(self) -> crate::operation::get_object_acl::GetObjectAclOutput {
        crate::operation::get_object_acl::GetObjectAclOutput {
            owner: self.owner,
            grants: self.grants,
            request_charged: self.request_charged,
            _extended_request_id: self._extended_request_id,
            _request_id: self._request_id,
        }
    }
}
