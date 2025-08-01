// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteClusterInput {
    /// <p>The string name or the Amazon Resource Name (ARN) of the SageMaker HyperPod cluster to delete.</p>
    pub cluster_name: ::std::option::Option<::std::string::String>,
}
impl DeleteClusterInput {
    /// <p>The string name or the Amazon Resource Name (ARN) of the SageMaker HyperPod cluster to delete.</p>
    pub fn cluster_name(&self) -> ::std::option::Option<&str> {
        self.cluster_name.as_deref()
    }
}
impl DeleteClusterInput {
    /// Creates a new builder-style object to manufacture [`DeleteClusterInput`](crate::operation::delete_cluster::DeleteClusterInput).
    pub fn builder() -> crate::operation::delete_cluster::builders::DeleteClusterInputBuilder {
        crate::operation::delete_cluster::builders::DeleteClusterInputBuilder::default()
    }
}

/// A builder for [`DeleteClusterInput`](crate::operation::delete_cluster::DeleteClusterInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteClusterInputBuilder {
    pub(crate) cluster_name: ::std::option::Option<::std::string::String>,
}
impl DeleteClusterInputBuilder {
    /// <p>The string name or the Amazon Resource Name (ARN) of the SageMaker HyperPod cluster to delete.</p>
    /// This field is required.
    pub fn cluster_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string name or the Amazon Resource Name (ARN) of the SageMaker HyperPod cluster to delete.</p>
    pub fn set_cluster_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_name = input;
        self
    }
    /// <p>The string name or the Amazon Resource Name (ARN) of the SageMaker HyperPod cluster to delete.</p>
    pub fn get_cluster_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_name
    }
    /// Consumes the builder and constructs a [`DeleteClusterInput`](crate::operation::delete_cluster::DeleteClusterInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_cluster::DeleteClusterInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_cluster::DeleteClusterInput {
            cluster_name: self.cluster_name,
        })
    }
}
