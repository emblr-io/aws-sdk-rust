// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details of the operation to create an Amazon S3 data access from an S3 bucket.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateS3DataAccessFromS3BucketRequestDetails {
    /// <p>Details about the S3 data access source asset.</p>
    pub asset_source: ::std::option::Option<crate::types::S3DataAccessAssetSourceEntry>,
    /// <p>The unique identifier for the data set associated with the creation of this Amazon S3 data access.</p>
    pub data_set_id: ::std::string::String,
    /// <p>The unique identifier for a revision.</p>
    pub revision_id: ::std::string::String,
}
impl CreateS3DataAccessFromS3BucketRequestDetails {
    /// <p>Details about the S3 data access source asset.</p>
    pub fn asset_source(&self) -> ::std::option::Option<&crate::types::S3DataAccessAssetSourceEntry> {
        self.asset_source.as_ref()
    }
    /// <p>The unique identifier for the data set associated with the creation of this Amazon S3 data access.</p>
    pub fn data_set_id(&self) -> &str {
        use std::ops::Deref;
        self.data_set_id.deref()
    }
    /// <p>The unique identifier for a revision.</p>
    pub fn revision_id(&self) -> &str {
        use std::ops::Deref;
        self.revision_id.deref()
    }
}
impl CreateS3DataAccessFromS3BucketRequestDetails {
    /// Creates a new builder-style object to manufacture [`CreateS3DataAccessFromS3BucketRequestDetails`](crate::types::CreateS3DataAccessFromS3BucketRequestDetails).
    pub fn builder() -> crate::types::builders::CreateS3DataAccessFromS3BucketRequestDetailsBuilder {
        crate::types::builders::CreateS3DataAccessFromS3BucketRequestDetailsBuilder::default()
    }
}

/// A builder for [`CreateS3DataAccessFromS3BucketRequestDetails`](crate::types::CreateS3DataAccessFromS3BucketRequestDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateS3DataAccessFromS3BucketRequestDetailsBuilder {
    pub(crate) asset_source: ::std::option::Option<crate::types::S3DataAccessAssetSourceEntry>,
    pub(crate) data_set_id: ::std::option::Option<::std::string::String>,
    pub(crate) revision_id: ::std::option::Option<::std::string::String>,
}
impl CreateS3DataAccessFromS3BucketRequestDetailsBuilder {
    /// <p>Details about the S3 data access source asset.</p>
    /// This field is required.
    pub fn asset_source(mut self, input: crate::types::S3DataAccessAssetSourceEntry) -> Self {
        self.asset_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the S3 data access source asset.</p>
    pub fn set_asset_source(mut self, input: ::std::option::Option<crate::types::S3DataAccessAssetSourceEntry>) -> Self {
        self.asset_source = input;
        self
    }
    /// <p>Details about the S3 data access source asset.</p>
    pub fn get_asset_source(&self) -> &::std::option::Option<crate::types::S3DataAccessAssetSourceEntry> {
        &self.asset_source
    }
    /// <p>The unique identifier for the data set associated with the creation of this Amazon S3 data access.</p>
    /// This field is required.
    pub fn data_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the data set associated with the creation of this Amazon S3 data access.</p>
    pub fn set_data_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_set_id = input;
        self
    }
    /// <p>The unique identifier for the data set associated with the creation of this Amazon S3 data access.</p>
    pub fn get_data_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_set_id
    }
    /// <p>The unique identifier for a revision.</p>
    /// This field is required.
    pub fn revision_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.revision_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for a revision.</p>
    pub fn set_revision_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.revision_id = input;
        self
    }
    /// <p>The unique identifier for a revision.</p>
    pub fn get_revision_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.revision_id
    }
    /// Consumes the builder and constructs a [`CreateS3DataAccessFromS3BucketRequestDetails`](crate::types::CreateS3DataAccessFromS3BucketRequestDetails).
    /// This method will fail if any of the following fields are not set:
    /// - [`data_set_id`](crate::types::builders::CreateS3DataAccessFromS3BucketRequestDetailsBuilder::data_set_id)
    /// - [`revision_id`](crate::types::builders::CreateS3DataAccessFromS3BucketRequestDetailsBuilder::revision_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::CreateS3DataAccessFromS3BucketRequestDetails, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CreateS3DataAccessFromS3BucketRequestDetails {
            asset_source: self.asset_source,
            data_set_id: self.data_set_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "data_set_id",
                    "data_set_id was not specified but it is required when building CreateS3DataAccessFromS3BucketRequestDetails",
                )
            })?,
            revision_id: self.revision_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "revision_id",
                    "revision_id was not specified but it is required when building CreateS3DataAccessFromS3BucketRequestDetails",
                )
            })?,
        })
    }
}
