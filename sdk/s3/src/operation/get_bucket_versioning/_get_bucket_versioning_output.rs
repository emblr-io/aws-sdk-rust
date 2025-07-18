// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetBucketVersioningOutput {
    /// <p>The versioning state of the bucket.</p>
    pub status: ::std::option::Option<crate::types::BucketVersioningStatus>,
    /// <p>Specifies whether MFA delete is enabled in the bucket versioning configuration. This element is only returned if the bucket has been configured with MFA delete. If the bucket has never been so configured, this element is not returned.</p>
    pub mfa_delete: ::std::option::Option<crate::types::MfaDeleteStatus>,
    _extended_request_id: Option<String>,
    _request_id: Option<String>,
}
impl GetBucketVersioningOutput {
    /// <p>The versioning state of the bucket.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::BucketVersioningStatus> {
        self.status.as_ref()
    }
    /// <p>Specifies whether MFA delete is enabled in the bucket versioning configuration. This element is only returned if the bucket has been configured with MFA delete. If the bucket has never been so configured, this element is not returned.</p>
    pub fn mfa_delete(&self) -> ::std::option::Option<&crate::types::MfaDeleteStatus> {
        self.mfa_delete.as_ref()
    }
}
impl crate::s3_request_id::RequestIdExt for GetBucketVersioningOutput {
    fn extended_request_id(&self) -> Option<&str> {
        self._extended_request_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetBucketVersioningOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetBucketVersioningOutput {
    /// Creates a new builder-style object to manufacture [`GetBucketVersioningOutput`](crate::operation::get_bucket_versioning::GetBucketVersioningOutput).
    pub fn builder() -> crate::operation::get_bucket_versioning::builders::GetBucketVersioningOutputBuilder {
        crate::operation::get_bucket_versioning::builders::GetBucketVersioningOutputBuilder::default()
    }
}

/// A builder for [`GetBucketVersioningOutput`](crate::operation::get_bucket_versioning::GetBucketVersioningOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetBucketVersioningOutputBuilder {
    pub(crate) status: ::std::option::Option<crate::types::BucketVersioningStatus>,
    pub(crate) mfa_delete: ::std::option::Option<crate::types::MfaDeleteStatus>,
    _extended_request_id: Option<String>,
    _request_id: Option<String>,
}
impl GetBucketVersioningOutputBuilder {
    /// <p>The versioning state of the bucket.</p>
    pub fn status(mut self, input: crate::types::BucketVersioningStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The versioning state of the bucket.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::BucketVersioningStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The versioning state of the bucket.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::BucketVersioningStatus> {
        &self.status
    }
    /// <p>Specifies whether MFA delete is enabled in the bucket versioning configuration. This element is only returned if the bucket has been configured with MFA delete. If the bucket has never been so configured, this element is not returned.</p>
    pub fn mfa_delete(mut self, input: crate::types::MfaDeleteStatus) -> Self {
        self.mfa_delete = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether MFA delete is enabled in the bucket versioning configuration. This element is only returned if the bucket has been configured with MFA delete. If the bucket has never been so configured, this element is not returned.</p>
    pub fn set_mfa_delete(mut self, input: ::std::option::Option<crate::types::MfaDeleteStatus>) -> Self {
        self.mfa_delete = input;
        self
    }
    /// <p>Specifies whether MFA delete is enabled in the bucket versioning configuration. This element is only returned if the bucket has been configured with MFA delete. If the bucket has never been so configured, this element is not returned.</p>
    pub fn get_mfa_delete(&self) -> &::std::option::Option<crate::types::MfaDeleteStatus> {
        &self.mfa_delete
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
    /// Consumes the builder and constructs a [`GetBucketVersioningOutput`](crate::operation::get_bucket_versioning::GetBucketVersioningOutput).
    pub fn build(self) -> crate::operation::get_bucket_versioning::GetBucketVersioningOutput {
        crate::operation::get_bucket_versioning::GetBucketVersioningOutput {
            status: self.status,
            mfa_delete: self.mfa_delete,
            _extended_request_id: self._extended_request_id,
            _request_id: self._request_id,
        }
    }
}
