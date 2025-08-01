// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Request object for UpdateStorage api. Its used to update the storage attributes for the cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateStorageInput {
    /// <p>The Amazon Resource Name (ARN) of the cluster to be updated.</p>
    pub cluster_arn: ::std::option::Option<::std::string::String>,
    /// <p>The version of cluster to update from. A successful operation will then generate a new version.</p>
    pub current_version: ::std::option::Option<::std::string::String>,
    /// <p>EBS volume provisioned throughput information.</p>
    pub provisioned_throughput: ::std::option::Option<crate::types::ProvisionedThroughput>,
    /// <p>Controls storage mode for supported storage tiers.</p>
    pub storage_mode: ::std::option::Option<crate::types::StorageMode>,
    /// <p>size of the EBS volume to update.</p>
    pub volume_size_gb: ::std::option::Option<i32>,
}
impl UpdateStorageInput {
    /// <p>The Amazon Resource Name (ARN) of the cluster to be updated.</p>
    pub fn cluster_arn(&self) -> ::std::option::Option<&str> {
        self.cluster_arn.as_deref()
    }
    /// <p>The version of cluster to update from. A successful operation will then generate a new version.</p>
    pub fn current_version(&self) -> ::std::option::Option<&str> {
        self.current_version.as_deref()
    }
    /// <p>EBS volume provisioned throughput information.</p>
    pub fn provisioned_throughput(&self) -> ::std::option::Option<&crate::types::ProvisionedThroughput> {
        self.provisioned_throughput.as_ref()
    }
    /// <p>Controls storage mode for supported storage tiers.</p>
    pub fn storage_mode(&self) -> ::std::option::Option<&crate::types::StorageMode> {
        self.storage_mode.as_ref()
    }
    /// <p>size of the EBS volume to update.</p>
    pub fn volume_size_gb(&self) -> ::std::option::Option<i32> {
        self.volume_size_gb
    }
}
impl UpdateStorageInput {
    /// Creates a new builder-style object to manufacture [`UpdateStorageInput`](crate::operation::update_storage::UpdateStorageInput).
    pub fn builder() -> crate::operation::update_storage::builders::UpdateStorageInputBuilder {
        crate::operation::update_storage::builders::UpdateStorageInputBuilder::default()
    }
}

/// A builder for [`UpdateStorageInput`](crate::operation::update_storage::UpdateStorageInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateStorageInputBuilder {
    pub(crate) cluster_arn: ::std::option::Option<::std::string::String>,
    pub(crate) current_version: ::std::option::Option<::std::string::String>,
    pub(crate) provisioned_throughput: ::std::option::Option<crate::types::ProvisionedThroughput>,
    pub(crate) storage_mode: ::std::option::Option<crate::types::StorageMode>,
    pub(crate) volume_size_gb: ::std::option::Option<i32>,
}
impl UpdateStorageInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the cluster to be updated.</p>
    /// This field is required.
    pub fn cluster_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the cluster to be updated.</p>
    pub fn set_cluster_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the cluster to be updated.</p>
    pub fn get_cluster_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_arn
    }
    /// <p>The version of cluster to update from. A successful operation will then generate a new version.</p>
    /// This field is required.
    pub fn current_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.current_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of cluster to update from. A successful operation will then generate a new version.</p>
    pub fn set_current_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.current_version = input;
        self
    }
    /// <p>The version of cluster to update from. A successful operation will then generate a new version.</p>
    pub fn get_current_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.current_version
    }
    /// <p>EBS volume provisioned throughput information.</p>
    pub fn provisioned_throughput(mut self, input: crate::types::ProvisionedThroughput) -> Self {
        self.provisioned_throughput = ::std::option::Option::Some(input);
        self
    }
    /// <p>EBS volume provisioned throughput information.</p>
    pub fn set_provisioned_throughput(mut self, input: ::std::option::Option<crate::types::ProvisionedThroughput>) -> Self {
        self.provisioned_throughput = input;
        self
    }
    /// <p>EBS volume provisioned throughput information.</p>
    pub fn get_provisioned_throughput(&self) -> &::std::option::Option<crate::types::ProvisionedThroughput> {
        &self.provisioned_throughput
    }
    /// <p>Controls storage mode for supported storage tiers.</p>
    pub fn storage_mode(mut self, input: crate::types::StorageMode) -> Self {
        self.storage_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Controls storage mode for supported storage tiers.</p>
    pub fn set_storage_mode(mut self, input: ::std::option::Option<crate::types::StorageMode>) -> Self {
        self.storage_mode = input;
        self
    }
    /// <p>Controls storage mode for supported storage tiers.</p>
    pub fn get_storage_mode(&self) -> &::std::option::Option<crate::types::StorageMode> {
        &self.storage_mode
    }
    /// <p>size of the EBS volume to update.</p>
    pub fn volume_size_gb(mut self, input: i32) -> Self {
        self.volume_size_gb = ::std::option::Option::Some(input);
        self
    }
    /// <p>size of the EBS volume to update.</p>
    pub fn set_volume_size_gb(mut self, input: ::std::option::Option<i32>) -> Self {
        self.volume_size_gb = input;
        self
    }
    /// <p>size of the EBS volume to update.</p>
    pub fn get_volume_size_gb(&self) -> &::std::option::Option<i32> {
        &self.volume_size_gb
    }
    /// Consumes the builder and constructs a [`UpdateStorageInput`](crate::operation::update_storage::UpdateStorageInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_storage::UpdateStorageInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_storage::UpdateStorageInput {
            cluster_arn: self.cluster_arn,
            current_version: self.current_version,
            provisioned_throughput: self.provisioned_throughput,
            storage_mode: self.storage_mode,
            volume_size_gb: self.volume_size_gb,
        })
    }
}
