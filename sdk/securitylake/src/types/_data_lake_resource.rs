// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides details of Amazon Security Lake object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataLakeResource {
    /// <p>The Amazon Resource Name (ARN) created by you to provide to the subscriber. For more information about ARNs and how to use them in policies, see the <a href="https://docs.aws.amazon.com/security-lake/latest/userguide/subscriber-management.html">Amazon Security Lake User Guide</a>.</p>
    pub data_lake_arn: ::std::string::String,
    /// <p>The Amazon Web Services Regions where Security Lake is enabled.</p>
    pub region: ::std::string::String,
    /// <p>The ARN for the Amazon Security Lake Amazon S3 bucket.</p>
    pub s3_bucket_arn: ::std::option::Option<::std::string::String>,
    /// <p>Provides encryption details of Amazon Security Lake object.</p>
    pub encryption_configuration: ::std::option::Option<crate::types::DataLakeEncryptionConfiguration>,
    /// <p>Provides lifecycle details of Amazon Security Lake object.</p>
    pub lifecycle_configuration: ::std::option::Option<crate::types::DataLakeLifecycleConfiguration>,
    /// <p>Provides replication details of Amazon Security Lake object.</p>
    pub replication_configuration: ::std::option::Option<crate::types::DataLakeReplicationConfiguration>,
    /// <p>Retrieves the status of the <code>CreateDatalake</code> API call for an account in Amazon Security Lake.</p>
    pub create_status: ::std::option::Option<crate::types::DataLakeStatus>,
    /// <p>The status of the last <code>UpdateDataLake </code>or <code>DeleteDataLake</code> API request.</p>
    pub update_status: ::std::option::Option<crate::types::DataLakeUpdateStatus>,
}
impl DataLakeResource {
    /// <p>The Amazon Resource Name (ARN) created by you to provide to the subscriber. For more information about ARNs and how to use them in policies, see the <a href="https://docs.aws.amazon.com/security-lake/latest/userguide/subscriber-management.html">Amazon Security Lake User Guide</a>.</p>
    pub fn data_lake_arn(&self) -> &str {
        use std::ops::Deref;
        self.data_lake_arn.deref()
    }
    /// <p>The Amazon Web Services Regions where Security Lake is enabled.</p>
    pub fn region(&self) -> &str {
        use std::ops::Deref;
        self.region.deref()
    }
    /// <p>The ARN for the Amazon Security Lake Amazon S3 bucket.</p>
    pub fn s3_bucket_arn(&self) -> ::std::option::Option<&str> {
        self.s3_bucket_arn.as_deref()
    }
    /// <p>Provides encryption details of Amazon Security Lake object.</p>
    pub fn encryption_configuration(&self) -> ::std::option::Option<&crate::types::DataLakeEncryptionConfiguration> {
        self.encryption_configuration.as_ref()
    }
    /// <p>Provides lifecycle details of Amazon Security Lake object.</p>
    pub fn lifecycle_configuration(&self) -> ::std::option::Option<&crate::types::DataLakeLifecycleConfiguration> {
        self.lifecycle_configuration.as_ref()
    }
    /// <p>Provides replication details of Amazon Security Lake object.</p>
    pub fn replication_configuration(&self) -> ::std::option::Option<&crate::types::DataLakeReplicationConfiguration> {
        self.replication_configuration.as_ref()
    }
    /// <p>Retrieves the status of the <code>CreateDatalake</code> API call for an account in Amazon Security Lake.</p>
    pub fn create_status(&self) -> ::std::option::Option<&crate::types::DataLakeStatus> {
        self.create_status.as_ref()
    }
    /// <p>The status of the last <code>UpdateDataLake </code>or <code>DeleteDataLake</code> API request.</p>
    pub fn update_status(&self) -> ::std::option::Option<&crate::types::DataLakeUpdateStatus> {
        self.update_status.as_ref()
    }
}
impl DataLakeResource {
    /// Creates a new builder-style object to manufacture [`DataLakeResource`](crate::types::DataLakeResource).
    pub fn builder() -> crate::types::builders::DataLakeResourceBuilder {
        crate::types::builders::DataLakeResourceBuilder::default()
    }
}

/// A builder for [`DataLakeResource`](crate::types::DataLakeResource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataLakeResourceBuilder {
    pub(crate) data_lake_arn: ::std::option::Option<::std::string::String>,
    pub(crate) region: ::std::option::Option<::std::string::String>,
    pub(crate) s3_bucket_arn: ::std::option::Option<::std::string::String>,
    pub(crate) encryption_configuration: ::std::option::Option<crate::types::DataLakeEncryptionConfiguration>,
    pub(crate) lifecycle_configuration: ::std::option::Option<crate::types::DataLakeLifecycleConfiguration>,
    pub(crate) replication_configuration: ::std::option::Option<crate::types::DataLakeReplicationConfiguration>,
    pub(crate) create_status: ::std::option::Option<crate::types::DataLakeStatus>,
    pub(crate) update_status: ::std::option::Option<crate::types::DataLakeUpdateStatus>,
}
impl DataLakeResourceBuilder {
    /// <p>The Amazon Resource Name (ARN) created by you to provide to the subscriber. For more information about ARNs and how to use them in policies, see the <a href="https://docs.aws.amazon.com/security-lake/latest/userguide/subscriber-management.html">Amazon Security Lake User Guide</a>.</p>
    /// This field is required.
    pub fn data_lake_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_lake_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) created by you to provide to the subscriber. For more information about ARNs and how to use them in policies, see the <a href="https://docs.aws.amazon.com/security-lake/latest/userguide/subscriber-management.html">Amazon Security Lake User Guide</a>.</p>
    pub fn set_data_lake_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_lake_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) created by you to provide to the subscriber. For more information about ARNs and how to use them in policies, see the <a href="https://docs.aws.amazon.com/security-lake/latest/userguide/subscriber-management.html">Amazon Security Lake User Guide</a>.</p>
    pub fn get_data_lake_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_lake_arn
    }
    /// <p>The Amazon Web Services Regions where Security Lake is enabled.</p>
    /// This field is required.
    pub fn region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services Regions where Security Lake is enabled.</p>
    pub fn set_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.region = input;
        self
    }
    /// <p>The Amazon Web Services Regions where Security Lake is enabled.</p>
    pub fn get_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.region
    }
    /// <p>The ARN for the Amazon Security Lake Amazon S3 bucket.</p>
    pub fn s3_bucket_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_bucket_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN for the Amazon Security Lake Amazon S3 bucket.</p>
    pub fn set_s3_bucket_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_bucket_arn = input;
        self
    }
    /// <p>The ARN for the Amazon Security Lake Amazon S3 bucket.</p>
    pub fn get_s3_bucket_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_bucket_arn
    }
    /// <p>Provides encryption details of Amazon Security Lake object.</p>
    pub fn encryption_configuration(mut self, input: crate::types::DataLakeEncryptionConfiguration) -> Self {
        self.encryption_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides encryption details of Amazon Security Lake object.</p>
    pub fn set_encryption_configuration(mut self, input: ::std::option::Option<crate::types::DataLakeEncryptionConfiguration>) -> Self {
        self.encryption_configuration = input;
        self
    }
    /// <p>Provides encryption details of Amazon Security Lake object.</p>
    pub fn get_encryption_configuration(&self) -> &::std::option::Option<crate::types::DataLakeEncryptionConfiguration> {
        &self.encryption_configuration
    }
    /// <p>Provides lifecycle details of Amazon Security Lake object.</p>
    pub fn lifecycle_configuration(mut self, input: crate::types::DataLakeLifecycleConfiguration) -> Self {
        self.lifecycle_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides lifecycle details of Amazon Security Lake object.</p>
    pub fn set_lifecycle_configuration(mut self, input: ::std::option::Option<crate::types::DataLakeLifecycleConfiguration>) -> Self {
        self.lifecycle_configuration = input;
        self
    }
    /// <p>Provides lifecycle details of Amazon Security Lake object.</p>
    pub fn get_lifecycle_configuration(&self) -> &::std::option::Option<crate::types::DataLakeLifecycleConfiguration> {
        &self.lifecycle_configuration
    }
    /// <p>Provides replication details of Amazon Security Lake object.</p>
    pub fn replication_configuration(mut self, input: crate::types::DataLakeReplicationConfiguration) -> Self {
        self.replication_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides replication details of Amazon Security Lake object.</p>
    pub fn set_replication_configuration(mut self, input: ::std::option::Option<crate::types::DataLakeReplicationConfiguration>) -> Self {
        self.replication_configuration = input;
        self
    }
    /// <p>Provides replication details of Amazon Security Lake object.</p>
    pub fn get_replication_configuration(&self) -> &::std::option::Option<crate::types::DataLakeReplicationConfiguration> {
        &self.replication_configuration
    }
    /// <p>Retrieves the status of the <code>CreateDatalake</code> API call for an account in Amazon Security Lake.</p>
    pub fn create_status(mut self, input: crate::types::DataLakeStatus) -> Self {
        self.create_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Retrieves the status of the <code>CreateDatalake</code> API call for an account in Amazon Security Lake.</p>
    pub fn set_create_status(mut self, input: ::std::option::Option<crate::types::DataLakeStatus>) -> Self {
        self.create_status = input;
        self
    }
    /// <p>Retrieves the status of the <code>CreateDatalake</code> API call for an account in Amazon Security Lake.</p>
    pub fn get_create_status(&self) -> &::std::option::Option<crate::types::DataLakeStatus> {
        &self.create_status
    }
    /// <p>The status of the last <code>UpdateDataLake </code>or <code>DeleteDataLake</code> API request.</p>
    pub fn update_status(mut self, input: crate::types::DataLakeUpdateStatus) -> Self {
        self.update_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the last <code>UpdateDataLake </code>or <code>DeleteDataLake</code> API request.</p>
    pub fn set_update_status(mut self, input: ::std::option::Option<crate::types::DataLakeUpdateStatus>) -> Self {
        self.update_status = input;
        self
    }
    /// <p>The status of the last <code>UpdateDataLake </code>or <code>DeleteDataLake</code> API request.</p>
    pub fn get_update_status(&self) -> &::std::option::Option<crate::types::DataLakeUpdateStatus> {
        &self.update_status
    }
    /// Consumes the builder and constructs a [`DataLakeResource`](crate::types::DataLakeResource).
    /// This method will fail if any of the following fields are not set:
    /// - [`data_lake_arn`](crate::types::builders::DataLakeResourceBuilder::data_lake_arn)
    /// - [`region`](crate::types::builders::DataLakeResourceBuilder::region)
    pub fn build(self) -> ::std::result::Result<crate::types::DataLakeResource, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DataLakeResource {
            data_lake_arn: self.data_lake_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "data_lake_arn",
                    "data_lake_arn was not specified but it is required when building DataLakeResource",
                )
            })?,
            region: self.region.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "region",
                    "region was not specified but it is required when building DataLakeResource",
                )
            })?,
            s3_bucket_arn: self.s3_bucket_arn,
            encryption_configuration: self.encryption_configuration,
            lifecycle_configuration: self.lifecycle_configuration,
            replication_configuration: self.replication_configuration,
            create_status: self.create_status,
            update_status: self.update_status,
        })
    }
}
