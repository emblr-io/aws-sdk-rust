// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteMultiRegionClusterInput {
    /// <p>The name of the multi-Region cluster to be deleted.</p>
    pub multi_region_cluster_name: ::std::option::Option<::std::string::String>,
}
impl DeleteMultiRegionClusterInput {
    /// <p>The name of the multi-Region cluster to be deleted.</p>
    pub fn multi_region_cluster_name(&self) -> ::std::option::Option<&str> {
        self.multi_region_cluster_name.as_deref()
    }
}
impl DeleteMultiRegionClusterInput {
    /// Creates a new builder-style object to manufacture [`DeleteMultiRegionClusterInput`](crate::operation::delete_multi_region_cluster::DeleteMultiRegionClusterInput).
    pub fn builder() -> crate::operation::delete_multi_region_cluster::builders::DeleteMultiRegionClusterInputBuilder {
        crate::operation::delete_multi_region_cluster::builders::DeleteMultiRegionClusterInputBuilder::default()
    }
}

/// A builder for [`DeleteMultiRegionClusterInput`](crate::operation::delete_multi_region_cluster::DeleteMultiRegionClusterInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteMultiRegionClusterInputBuilder {
    pub(crate) multi_region_cluster_name: ::std::option::Option<::std::string::String>,
}
impl DeleteMultiRegionClusterInputBuilder {
    /// <p>The name of the multi-Region cluster to be deleted.</p>
    /// This field is required.
    pub fn multi_region_cluster_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.multi_region_cluster_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the multi-Region cluster to be deleted.</p>
    pub fn set_multi_region_cluster_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.multi_region_cluster_name = input;
        self
    }
    /// <p>The name of the multi-Region cluster to be deleted.</p>
    pub fn get_multi_region_cluster_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.multi_region_cluster_name
    }
    /// Consumes the builder and constructs a [`DeleteMultiRegionClusterInput`](crate::operation::delete_multi_region_cluster::DeleteMultiRegionClusterInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_multi_region_cluster::DeleteMultiRegionClusterInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_multi_region_cluster::DeleteMultiRegionClusterInput {
            multi_region_cluster_name: self.multi_region_cluster_name,
        })
    }
}
