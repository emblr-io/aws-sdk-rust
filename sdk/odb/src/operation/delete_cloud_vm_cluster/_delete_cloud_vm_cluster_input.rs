// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteCloudVmClusterInput {
    /// <p>The unique identifier of the VM cluster to delete.</p>
    pub cloud_vm_cluster_id: ::std::option::Option<::std::string::String>,
}
impl DeleteCloudVmClusterInput {
    /// <p>The unique identifier of the VM cluster to delete.</p>
    pub fn cloud_vm_cluster_id(&self) -> ::std::option::Option<&str> {
        self.cloud_vm_cluster_id.as_deref()
    }
}
impl DeleteCloudVmClusterInput {
    /// Creates a new builder-style object to manufacture [`DeleteCloudVmClusterInput`](crate::operation::delete_cloud_vm_cluster::DeleteCloudVmClusterInput).
    pub fn builder() -> crate::operation::delete_cloud_vm_cluster::builders::DeleteCloudVmClusterInputBuilder {
        crate::operation::delete_cloud_vm_cluster::builders::DeleteCloudVmClusterInputBuilder::default()
    }
}

/// A builder for [`DeleteCloudVmClusterInput`](crate::operation::delete_cloud_vm_cluster::DeleteCloudVmClusterInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteCloudVmClusterInputBuilder {
    pub(crate) cloud_vm_cluster_id: ::std::option::Option<::std::string::String>,
}
impl DeleteCloudVmClusterInputBuilder {
    /// <p>The unique identifier of the VM cluster to delete.</p>
    /// This field is required.
    pub fn cloud_vm_cluster_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cloud_vm_cluster_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the VM cluster to delete.</p>
    pub fn set_cloud_vm_cluster_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cloud_vm_cluster_id = input;
        self
    }
    /// <p>The unique identifier of the VM cluster to delete.</p>
    pub fn get_cloud_vm_cluster_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.cloud_vm_cluster_id
    }
    /// Consumes the builder and constructs a [`DeleteCloudVmClusterInput`](crate::operation::delete_cloud_vm_cluster::DeleteCloudVmClusterInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_cloud_vm_cluster::DeleteCloudVmClusterInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_cloud_vm_cluster::DeleteCloudVmClusterInput {
            cloud_vm_cluster_id: self.cloud_vm_cluster_id,
        })
    }
}
