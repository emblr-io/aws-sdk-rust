// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteBucketMetadataTableConfigurationOutput {
    _extended_request_id: Option<String>,
    _request_id: Option<String>,
}
impl crate::s3_request_id::RequestIdExt for DeleteBucketMetadataTableConfigurationOutput {
    fn extended_request_id(&self) -> Option<&str> {
        self._extended_request_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteBucketMetadataTableConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteBucketMetadataTableConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`DeleteBucketMetadataTableConfigurationOutput`](crate::operation::delete_bucket_metadata_table_configuration::DeleteBucketMetadataTableConfigurationOutput).
    pub fn builder() -> crate::operation::delete_bucket_metadata_table_configuration::builders::DeleteBucketMetadataTableConfigurationOutputBuilder {
        crate::operation::delete_bucket_metadata_table_configuration::builders::DeleteBucketMetadataTableConfigurationOutputBuilder::default()
    }
}

/// A builder for [`DeleteBucketMetadataTableConfigurationOutput`](crate::operation::delete_bucket_metadata_table_configuration::DeleteBucketMetadataTableConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteBucketMetadataTableConfigurationOutputBuilder {
    _extended_request_id: Option<String>,
    _request_id: Option<String>,
}
impl DeleteBucketMetadataTableConfigurationOutputBuilder {
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
    /// Consumes the builder and constructs a [`DeleteBucketMetadataTableConfigurationOutput`](crate::operation::delete_bucket_metadata_table_configuration::DeleteBucketMetadataTableConfigurationOutput).
    pub fn build(self) -> crate::operation::delete_bucket_metadata_table_configuration::DeleteBucketMetadataTableConfigurationOutput {
        crate::operation::delete_bucket_metadata_table_configuration::DeleteBucketMetadataTableConfigurationOutput {
            _extended_request_id: self._extended_request_id,
            _request_id: self._request_id,
        }
    }
}
