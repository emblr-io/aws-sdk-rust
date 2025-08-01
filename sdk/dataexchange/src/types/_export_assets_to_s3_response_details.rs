// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about the export to Amazon S3 response.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExportAssetsToS3ResponseDetails {
    /// <p>The destination in Amazon S3 where the asset is exported.</p>
    pub asset_destinations: ::std::vec::Vec<crate::types::AssetDestinationEntry>,
    /// <p>The unique identifier for the data set associated with this export job.</p>
    pub data_set_id: ::std::string::String,
    /// <p>Encryption configuration of the export job.</p>
    pub encryption: ::std::option::Option<crate::types::ExportServerSideEncryption>,
    /// <p>The unique identifier for the revision associated with this export response.</p>
    pub revision_id: ::std::string::String,
}
impl ExportAssetsToS3ResponseDetails {
    /// <p>The destination in Amazon S3 where the asset is exported.</p>
    pub fn asset_destinations(&self) -> &[crate::types::AssetDestinationEntry] {
        use std::ops::Deref;
        self.asset_destinations.deref()
    }
    /// <p>The unique identifier for the data set associated with this export job.</p>
    pub fn data_set_id(&self) -> &str {
        use std::ops::Deref;
        self.data_set_id.deref()
    }
    /// <p>Encryption configuration of the export job.</p>
    pub fn encryption(&self) -> ::std::option::Option<&crate::types::ExportServerSideEncryption> {
        self.encryption.as_ref()
    }
    /// <p>The unique identifier for the revision associated with this export response.</p>
    pub fn revision_id(&self) -> &str {
        use std::ops::Deref;
        self.revision_id.deref()
    }
}
impl ExportAssetsToS3ResponseDetails {
    /// Creates a new builder-style object to manufacture [`ExportAssetsToS3ResponseDetails`](crate::types::ExportAssetsToS3ResponseDetails).
    pub fn builder() -> crate::types::builders::ExportAssetsToS3ResponseDetailsBuilder {
        crate::types::builders::ExportAssetsToS3ResponseDetailsBuilder::default()
    }
}

/// A builder for [`ExportAssetsToS3ResponseDetails`](crate::types::ExportAssetsToS3ResponseDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExportAssetsToS3ResponseDetailsBuilder {
    pub(crate) asset_destinations: ::std::option::Option<::std::vec::Vec<crate::types::AssetDestinationEntry>>,
    pub(crate) data_set_id: ::std::option::Option<::std::string::String>,
    pub(crate) encryption: ::std::option::Option<crate::types::ExportServerSideEncryption>,
    pub(crate) revision_id: ::std::option::Option<::std::string::String>,
}
impl ExportAssetsToS3ResponseDetailsBuilder {
    /// Appends an item to `asset_destinations`.
    ///
    /// To override the contents of this collection use [`set_asset_destinations`](Self::set_asset_destinations).
    ///
    /// <p>The destination in Amazon S3 where the asset is exported.</p>
    pub fn asset_destinations(mut self, input: crate::types::AssetDestinationEntry) -> Self {
        let mut v = self.asset_destinations.unwrap_or_default();
        v.push(input);
        self.asset_destinations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The destination in Amazon S3 where the asset is exported.</p>
    pub fn set_asset_destinations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AssetDestinationEntry>>) -> Self {
        self.asset_destinations = input;
        self
    }
    /// <p>The destination in Amazon S3 where the asset is exported.</p>
    pub fn get_asset_destinations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AssetDestinationEntry>> {
        &self.asset_destinations
    }
    /// <p>The unique identifier for the data set associated with this export job.</p>
    /// This field is required.
    pub fn data_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the data set associated with this export job.</p>
    pub fn set_data_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_set_id = input;
        self
    }
    /// <p>The unique identifier for the data set associated with this export job.</p>
    pub fn get_data_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_set_id
    }
    /// <p>Encryption configuration of the export job.</p>
    pub fn encryption(mut self, input: crate::types::ExportServerSideEncryption) -> Self {
        self.encryption = ::std::option::Option::Some(input);
        self
    }
    /// <p>Encryption configuration of the export job.</p>
    pub fn set_encryption(mut self, input: ::std::option::Option<crate::types::ExportServerSideEncryption>) -> Self {
        self.encryption = input;
        self
    }
    /// <p>Encryption configuration of the export job.</p>
    pub fn get_encryption(&self) -> &::std::option::Option<crate::types::ExportServerSideEncryption> {
        &self.encryption
    }
    /// <p>The unique identifier for the revision associated with this export response.</p>
    /// This field is required.
    pub fn revision_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.revision_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the revision associated with this export response.</p>
    pub fn set_revision_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.revision_id = input;
        self
    }
    /// <p>The unique identifier for the revision associated with this export response.</p>
    pub fn get_revision_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.revision_id
    }
    /// Consumes the builder and constructs a [`ExportAssetsToS3ResponseDetails`](crate::types::ExportAssetsToS3ResponseDetails).
    /// This method will fail if any of the following fields are not set:
    /// - [`asset_destinations`](crate::types::builders::ExportAssetsToS3ResponseDetailsBuilder::asset_destinations)
    /// - [`data_set_id`](crate::types::builders::ExportAssetsToS3ResponseDetailsBuilder::data_set_id)
    /// - [`revision_id`](crate::types::builders::ExportAssetsToS3ResponseDetailsBuilder::revision_id)
    pub fn build(self) -> ::std::result::Result<crate::types::ExportAssetsToS3ResponseDetails, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ExportAssetsToS3ResponseDetails {
            asset_destinations: self.asset_destinations.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "asset_destinations",
                    "asset_destinations was not specified but it is required when building ExportAssetsToS3ResponseDetails",
                )
            })?,
            data_set_id: self.data_set_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "data_set_id",
                    "data_set_id was not specified but it is required when building ExportAssetsToS3ResponseDetails",
                )
            })?,
            encryption: self.encryption,
            revision_id: self.revision_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "revision_id",
                    "revision_id was not specified but it is required when building ExportAssetsToS3ResponseDetails",
                )
            })?,
        })
    }
}
