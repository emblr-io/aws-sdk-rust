// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A container for the Amazon S3 Storage Lens configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StorageLensConfiguration {
    /// <p>A container for the Amazon S3 Storage Lens configuration ID.</p>
    pub id: ::std::string::String,
    /// <p>A container for all the account-level configurations of your S3 Storage Lens configuration.</p>
    pub account_level: ::std::option::Option<crate::types::AccountLevel>,
    /// <p>A container for what is included in this configuration. This container can only be valid if there is no <code>Exclude</code> container submitted, and it's not empty.</p>
    pub include: ::std::option::Option<crate::types::Include>,
    /// <p>A container for what is excluded in this configuration. This container can only be valid if there is no <code>Include</code> container submitted, and it's not empty.</p>
    pub exclude: ::std::option::Option<crate::types::Exclude>,
    /// <p>A container to specify the properties of your S3 Storage Lens metrics export including, the destination, schema and format.</p>
    pub data_export: ::std::option::Option<crate::types::StorageLensDataExport>,
    /// <p>A container for whether the S3 Storage Lens configuration is enabled.</p>
    pub is_enabled: bool,
    /// <p>A container for the Amazon Web Services organization for this S3 Storage Lens configuration.</p>
    pub aws_org: ::std::option::Option<crate::types::StorageLensAwsOrg>,
    /// <p>The Amazon Resource Name (ARN) of the S3 Storage Lens configuration. This property is read-only and follows the following format: <code> arn:aws:s3:<i>us-east-1</i>:<i>example-account-id</i>:storage-lens/<i>your-dashboard-name</i> </code></p>
    pub storage_lens_arn: ::std::option::Option<::std::string::String>,
}
impl StorageLensConfiguration {
    /// <p>A container for the Amazon S3 Storage Lens configuration ID.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>A container for all the account-level configurations of your S3 Storage Lens configuration.</p>
    pub fn account_level(&self) -> ::std::option::Option<&crate::types::AccountLevel> {
        self.account_level.as_ref()
    }
    /// <p>A container for what is included in this configuration. This container can only be valid if there is no <code>Exclude</code> container submitted, and it's not empty.</p>
    pub fn include(&self) -> ::std::option::Option<&crate::types::Include> {
        self.include.as_ref()
    }
    /// <p>A container for what is excluded in this configuration. This container can only be valid if there is no <code>Include</code> container submitted, and it's not empty.</p>
    pub fn exclude(&self) -> ::std::option::Option<&crate::types::Exclude> {
        self.exclude.as_ref()
    }
    /// <p>A container to specify the properties of your S3 Storage Lens metrics export including, the destination, schema and format.</p>
    pub fn data_export(&self) -> ::std::option::Option<&crate::types::StorageLensDataExport> {
        self.data_export.as_ref()
    }
    /// <p>A container for whether the S3 Storage Lens configuration is enabled.</p>
    pub fn is_enabled(&self) -> bool {
        self.is_enabled
    }
    /// <p>A container for the Amazon Web Services organization for this S3 Storage Lens configuration.</p>
    pub fn aws_org(&self) -> ::std::option::Option<&crate::types::StorageLensAwsOrg> {
        self.aws_org.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the S3 Storage Lens configuration. This property is read-only and follows the following format: <code> arn:aws:s3:<i>us-east-1</i>:<i>example-account-id</i>:storage-lens/<i>your-dashboard-name</i> </code></p>
    pub fn storage_lens_arn(&self) -> ::std::option::Option<&str> {
        self.storage_lens_arn.as_deref()
    }
}
impl StorageLensConfiguration {
    /// Creates a new builder-style object to manufacture [`StorageLensConfiguration`](crate::types::StorageLensConfiguration).
    pub fn builder() -> crate::types::builders::StorageLensConfigurationBuilder {
        crate::types::builders::StorageLensConfigurationBuilder::default()
    }
}

/// A builder for [`StorageLensConfiguration`](crate::types::StorageLensConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StorageLensConfigurationBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) account_level: ::std::option::Option<crate::types::AccountLevel>,
    pub(crate) include: ::std::option::Option<crate::types::Include>,
    pub(crate) exclude: ::std::option::Option<crate::types::Exclude>,
    pub(crate) data_export: ::std::option::Option<crate::types::StorageLensDataExport>,
    pub(crate) is_enabled: ::std::option::Option<bool>,
    pub(crate) aws_org: ::std::option::Option<crate::types::StorageLensAwsOrg>,
    pub(crate) storage_lens_arn: ::std::option::Option<::std::string::String>,
}
impl StorageLensConfigurationBuilder {
    /// <p>A container for the Amazon S3 Storage Lens configuration ID.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A container for the Amazon S3 Storage Lens configuration ID.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>A container for the Amazon S3 Storage Lens configuration ID.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>A container for all the account-level configurations of your S3 Storage Lens configuration.</p>
    /// This field is required.
    pub fn account_level(mut self, input: crate::types::AccountLevel) -> Self {
        self.account_level = ::std::option::Option::Some(input);
        self
    }
    /// <p>A container for all the account-level configurations of your S3 Storage Lens configuration.</p>
    pub fn set_account_level(mut self, input: ::std::option::Option<crate::types::AccountLevel>) -> Self {
        self.account_level = input;
        self
    }
    /// <p>A container for all the account-level configurations of your S3 Storage Lens configuration.</p>
    pub fn get_account_level(&self) -> &::std::option::Option<crate::types::AccountLevel> {
        &self.account_level
    }
    /// <p>A container for what is included in this configuration. This container can only be valid if there is no <code>Exclude</code> container submitted, and it's not empty.</p>
    pub fn include(mut self, input: crate::types::Include) -> Self {
        self.include = ::std::option::Option::Some(input);
        self
    }
    /// <p>A container for what is included in this configuration. This container can only be valid if there is no <code>Exclude</code> container submitted, and it's not empty.</p>
    pub fn set_include(mut self, input: ::std::option::Option<crate::types::Include>) -> Self {
        self.include = input;
        self
    }
    /// <p>A container for what is included in this configuration. This container can only be valid if there is no <code>Exclude</code> container submitted, and it's not empty.</p>
    pub fn get_include(&self) -> &::std::option::Option<crate::types::Include> {
        &self.include
    }
    /// <p>A container for what is excluded in this configuration. This container can only be valid if there is no <code>Include</code> container submitted, and it's not empty.</p>
    pub fn exclude(mut self, input: crate::types::Exclude) -> Self {
        self.exclude = ::std::option::Option::Some(input);
        self
    }
    /// <p>A container for what is excluded in this configuration. This container can only be valid if there is no <code>Include</code> container submitted, and it's not empty.</p>
    pub fn set_exclude(mut self, input: ::std::option::Option<crate::types::Exclude>) -> Self {
        self.exclude = input;
        self
    }
    /// <p>A container for what is excluded in this configuration. This container can only be valid if there is no <code>Include</code> container submitted, and it's not empty.</p>
    pub fn get_exclude(&self) -> &::std::option::Option<crate::types::Exclude> {
        &self.exclude
    }
    /// <p>A container to specify the properties of your S3 Storage Lens metrics export including, the destination, schema and format.</p>
    pub fn data_export(mut self, input: crate::types::StorageLensDataExport) -> Self {
        self.data_export = ::std::option::Option::Some(input);
        self
    }
    /// <p>A container to specify the properties of your S3 Storage Lens metrics export including, the destination, schema and format.</p>
    pub fn set_data_export(mut self, input: ::std::option::Option<crate::types::StorageLensDataExport>) -> Self {
        self.data_export = input;
        self
    }
    /// <p>A container to specify the properties of your S3 Storage Lens metrics export including, the destination, schema and format.</p>
    pub fn get_data_export(&self) -> &::std::option::Option<crate::types::StorageLensDataExport> {
        &self.data_export
    }
    /// <p>A container for whether the S3 Storage Lens configuration is enabled.</p>
    /// This field is required.
    pub fn is_enabled(mut self, input: bool) -> Self {
        self.is_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>A container for whether the S3 Storage Lens configuration is enabled.</p>
    pub fn set_is_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_enabled = input;
        self
    }
    /// <p>A container for whether the S3 Storage Lens configuration is enabled.</p>
    pub fn get_is_enabled(&self) -> &::std::option::Option<bool> {
        &self.is_enabled
    }
    /// <p>A container for the Amazon Web Services organization for this S3 Storage Lens configuration.</p>
    pub fn aws_org(mut self, input: crate::types::StorageLensAwsOrg) -> Self {
        self.aws_org = ::std::option::Option::Some(input);
        self
    }
    /// <p>A container for the Amazon Web Services organization for this S3 Storage Lens configuration.</p>
    pub fn set_aws_org(mut self, input: ::std::option::Option<crate::types::StorageLensAwsOrg>) -> Self {
        self.aws_org = input;
        self
    }
    /// <p>A container for the Amazon Web Services organization for this S3 Storage Lens configuration.</p>
    pub fn get_aws_org(&self) -> &::std::option::Option<crate::types::StorageLensAwsOrg> {
        &self.aws_org
    }
    /// <p>The Amazon Resource Name (ARN) of the S3 Storage Lens configuration. This property is read-only and follows the following format: <code> arn:aws:s3:<i>us-east-1</i>:<i>example-account-id</i>:storage-lens/<i>your-dashboard-name</i> </code></p>
    pub fn storage_lens_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.storage_lens_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the S3 Storage Lens configuration. This property is read-only and follows the following format: <code> arn:aws:s3:<i>us-east-1</i>:<i>example-account-id</i>:storage-lens/<i>your-dashboard-name</i> </code></p>
    pub fn set_storage_lens_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.storage_lens_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the S3 Storage Lens configuration. This property is read-only and follows the following format: <code> arn:aws:s3:<i>us-east-1</i>:<i>example-account-id</i>:storage-lens/<i>your-dashboard-name</i> </code></p>
    pub fn get_storage_lens_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.storage_lens_arn
    }
    /// Consumes the builder and constructs a [`StorageLensConfiguration`](crate::types::StorageLensConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::StorageLensConfigurationBuilder::id)
    pub fn build(self) -> ::std::result::Result<crate::types::StorageLensConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::StorageLensConfiguration {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building StorageLensConfiguration",
                )
            })?,
            account_level: self.account_level,
            include: self.include,
            exclude: self.exclude,
            data_export: self.data_export,
            is_enabled: self.is_enabled.unwrap_or_default(),
            aws_org: self.aws_org,
            storage_lens_arn: self.storage_lens_arn,
        })
    }
}
