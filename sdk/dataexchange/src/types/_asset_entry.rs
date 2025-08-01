// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An asset in AWS Data Exchange is a piece of data (Amazon S3 object) or a means of fulfilling data (Amazon Redshift datashare or Amazon API Gateway API, AWS Lake Formation data permission, or Amazon S3 data access). The asset can be a structured data file, an image file, or some other data file that can be stored as an Amazon S3 object, an Amazon API Gateway API, or an Amazon Redshift datashare, an AWS Lake Formation data permission, or an Amazon S3 data access. When you create an import job for your files, API Gateway APIs, Amazon Redshift datashares, AWS Lake Formation data permission, or Amazon S3 data access, you create an asset in AWS Data Exchange.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssetEntry {
    /// <p>The ARN for the asset.</p>
    pub arn: ::std::string::String,
    /// <p>Details about the asset.</p>
    pub asset_details: ::std::option::Option<crate::types::AssetDetails>,
    /// <p>The type of asset that is added to a data set.</p>
    pub asset_type: crate::types::AssetType,
    /// <p>The date and time that the asset was created, in ISO 8601 format.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>The unique identifier for the data set associated with this asset.</p>
    pub data_set_id: ::std::string::String,
    /// <p>The unique identifier for the asset.</p>
    pub id: ::std::string::String,
    /// <p>The name of the asset. When importing from Amazon S3, the Amazon S3 object key is used as the asset name. When exporting to Amazon S3, the asset name is used as default target Amazon S3 object key. When importing from Amazon API Gateway API, the API name is used as the asset name. When importing from Amazon Redshift, the datashare name is used as the asset name. When importing from AWS Lake Formation, the static values of "Database(s) included in LF-tag policy" or "Table(s) included in LF-tag policy" are used as the asset name.</p>
    pub name: ::std::string::String,
    /// <p>The unique identifier for the revision associated with this asset.</p>
    pub revision_id: ::std::string::String,
    /// <p>The asset ID of the owned asset corresponding to the entitled asset being viewed. This parameter is returned when an asset owner is viewing the entitled copy of its owned asset.</p>
    pub source_id: ::std::option::Option<::std::string::String>,
    /// <p>The date and time that the asset was last updated, in ISO 8601 format.</p>
    pub updated_at: ::aws_smithy_types::DateTime,
}
impl AssetEntry {
    /// <p>The ARN for the asset.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>Details about the asset.</p>
    pub fn asset_details(&self) -> ::std::option::Option<&crate::types::AssetDetails> {
        self.asset_details.as_ref()
    }
    /// <p>The type of asset that is added to a data set.</p>
    pub fn asset_type(&self) -> &crate::types::AssetType {
        &self.asset_type
    }
    /// <p>The date and time that the asset was created, in ISO 8601 format.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>The unique identifier for the data set associated with this asset.</p>
    pub fn data_set_id(&self) -> &str {
        use std::ops::Deref;
        self.data_set_id.deref()
    }
    /// <p>The unique identifier for the asset.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The name of the asset. When importing from Amazon S3, the Amazon S3 object key is used as the asset name. When exporting to Amazon S3, the asset name is used as default target Amazon S3 object key. When importing from Amazon API Gateway API, the API name is used as the asset name. When importing from Amazon Redshift, the datashare name is used as the asset name. When importing from AWS Lake Formation, the static values of "Database(s) included in LF-tag policy" or "Table(s) included in LF-tag policy" are used as the asset name.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The unique identifier for the revision associated with this asset.</p>
    pub fn revision_id(&self) -> &str {
        use std::ops::Deref;
        self.revision_id.deref()
    }
    /// <p>The asset ID of the owned asset corresponding to the entitled asset being viewed. This parameter is returned when an asset owner is viewing the entitled copy of its owned asset.</p>
    pub fn source_id(&self) -> ::std::option::Option<&str> {
        self.source_id.as_deref()
    }
    /// <p>The date and time that the asset was last updated, in ISO 8601 format.</p>
    pub fn updated_at(&self) -> &::aws_smithy_types::DateTime {
        &self.updated_at
    }
}
impl AssetEntry {
    /// Creates a new builder-style object to manufacture [`AssetEntry`](crate::types::AssetEntry).
    pub fn builder() -> crate::types::builders::AssetEntryBuilder {
        crate::types::builders::AssetEntryBuilder::default()
    }
}

/// A builder for [`AssetEntry`](crate::types::AssetEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssetEntryBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) asset_details: ::std::option::Option<crate::types::AssetDetails>,
    pub(crate) asset_type: ::std::option::Option<crate::types::AssetType>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) data_set_id: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) revision_id: ::std::option::Option<::std::string::String>,
    pub(crate) source_id: ::std::option::Option<::std::string::String>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl AssetEntryBuilder {
    /// <p>The ARN for the asset.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN for the asset.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN for the asset.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>Details about the asset.</p>
    /// This field is required.
    pub fn asset_details(mut self, input: crate::types::AssetDetails) -> Self {
        self.asset_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the asset.</p>
    pub fn set_asset_details(mut self, input: ::std::option::Option<crate::types::AssetDetails>) -> Self {
        self.asset_details = input;
        self
    }
    /// <p>Details about the asset.</p>
    pub fn get_asset_details(&self) -> &::std::option::Option<crate::types::AssetDetails> {
        &self.asset_details
    }
    /// <p>The type of asset that is added to a data set.</p>
    /// This field is required.
    pub fn asset_type(mut self, input: crate::types::AssetType) -> Self {
        self.asset_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of asset that is added to a data set.</p>
    pub fn set_asset_type(mut self, input: ::std::option::Option<crate::types::AssetType>) -> Self {
        self.asset_type = input;
        self
    }
    /// <p>The type of asset that is added to a data set.</p>
    pub fn get_asset_type(&self) -> &::std::option::Option<crate::types::AssetType> {
        &self.asset_type
    }
    /// <p>The date and time that the asset was created, in ISO 8601 format.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the asset was created, in ISO 8601 format.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time that the asset was created, in ISO 8601 format.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The unique identifier for the data set associated with this asset.</p>
    /// This field is required.
    pub fn data_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the data set associated with this asset.</p>
    pub fn set_data_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_set_id = input;
        self
    }
    /// <p>The unique identifier for the data set associated with this asset.</p>
    pub fn get_data_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_set_id
    }
    /// <p>The unique identifier for the asset.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the asset.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier for the asset.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name of the asset. When importing from Amazon S3, the Amazon S3 object key is used as the asset name. When exporting to Amazon S3, the asset name is used as default target Amazon S3 object key. When importing from Amazon API Gateway API, the API name is used as the asset name. When importing from Amazon Redshift, the datashare name is used as the asset name. When importing from AWS Lake Formation, the static values of "Database(s) included in LF-tag policy" or "Table(s) included in LF-tag policy" are used as the asset name.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the asset. When importing from Amazon S3, the Amazon S3 object key is used as the asset name. When exporting to Amazon S3, the asset name is used as default target Amazon S3 object key. When importing from Amazon API Gateway API, the API name is used as the asset name. When importing from Amazon Redshift, the datashare name is used as the asset name. When importing from AWS Lake Formation, the static values of "Database(s) included in LF-tag policy" or "Table(s) included in LF-tag policy" are used as the asset name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the asset. When importing from Amazon S3, the Amazon S3 object key is used as the asset name. When exporting to Amazon S3, the asset name is used as default target Amazon S3 object key. When importing from Amazon API Gateway API, the API name is used as the asset name. When importing from Amazon Redshift, the datashare name is used as the asset name. When importing from AWS Lake Formation, the static values of "Database(s) included in LF-tag policy" or "Table(s) included in LF-tag policy" are used as the asset name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The unique identifier for the revision associated with this asset.</p>
    /// This field is required.
    pub fn revision_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.revision_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the revision associated with this asset.</p>
    pub fn set_revision_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.revision_id = input;
        self
    }
    /// <p>The unique identifier for the revision associated with this asset.</p>
    pub fn get_revision_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.revision_id
    }
    /// <p>The asset ID of the owned asset corresponding to the entitled asset being viewed. This parameter is returned when an asset owner is viewing the entitled copy of its owned asset.</p>
    pub fn source_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The asset ID of the owned asset corresponding to the entitled asset being viewed. This parameter is returned when an asset owner is viewing the entitled copy of its owned asset.</p>
    pub fn set_source_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_id = input;
        self
    }
    /// <p>The asset ID of the owned asset corresponding to the entitled asset being viewed. This parameter is returned when an asset owner is viewing the entitled copy of its owned asset.</p>
    pub fn get_source_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_id
    }
    /// <p>The date and time that the asset was last updated, in ISO 8601 format.</p>
    /// This field is required.
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the asset was last updated, in ISO 8601 format.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The date and time that the asset was last updated, in ISO 8601 format.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// Consumes the builder and constructs a [`AssetEntry`](crate::types::AssetEntry).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::types::builders::AssetEntryBuilder::arn)
    /// - [`asset_type`](crate::types::builders::AssetEntryBuilder::asset_type)
    /// - [`created_at`](crate::types::builders::AssetEntryBuilder::created_at)
    /// - [`data_set_id`](crate::types::builders::AssetEntryBuilder::data_set_id)
    /// - [`id`](crate::types::builders::AssetEntryBuilder::id)
    /// - [`name`](crate::types::builders::AssetEntryBuilder::name)
    /// - [`revision_id`](crate::types::builders::AssetEntryBuilder::revision_id)
    /// - [`updated_at`](crate::types::builders::AssetEntryBuilder::updated_at)
    pub fn build(self) -> ::std::result::Result<crate::types::AssetEntry, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AssetEntry {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building AssetEntry",
                )
            })?,
            asset_details: self.asset_details,
            asset_type: self.asset_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "asset_type",
                    "asset_type was not specified but it is required when building AssetEntry",
                )
            })?,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building AssetEntry",
                )
            })?,
            data_set_id: self.data_set_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "data_set_id",
                    "data_set_id was not specified but it is required when building AssetEntry",
                )
            })?,
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building AssetEntry",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building AssetEntry",
                )
            })?,
            revision_id: self.revision_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "revision_id",
                    "revision_id was not specified but it is required when building AssetEntry",
                )
            })?,
            source_id: self.source_id,
            updated_at: self.updated_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "updated_at",
                    "updated_at was not specified but it is required when building AssetEntry",
                )
            })?,
        })
    }
}
