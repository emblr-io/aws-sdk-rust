// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeVirtualClusterOutput {
    /// <p>This output displays information about the specified virtual cluster.</p>
    pub virtual_cluster: ::std::option::Option<crate::types::VirtualCluster>,
    _request_id: Option<String>,
}
impl DescribeVirtualClusterOutput {
    /// <p>This output displays information about the specified virtual cluster.</p>
    pub fn virtual_cluster(&self) -> ::std::option::Option<&crate::types::VirtualCluster> {
        self.virtual_cluster.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeVirtualClusterOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeVirtualClusterOutput {
    /// Creates a new builder-style object to manufacture [`DescribeVirtualClusterOutput`](crate::operation::describe_virtual_cluster::DescribeVirtualClusterOutput).
    pub fn builder() -> crate::operation::describe_virtual_cluster::builders::DescribeVirtualClusterOutputBuilder {
        crate::operation::describe_virtual_cluster::builders::DescribeVirtualClusterOutputBuilder::default()
    }
}

/// A builder for [`DescribeVirtualClusterOutput`](crate::operation::describe_virtual_cluster::DescribeVirtualClusterOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeVirtualClusterOutputBuilder {
    pub(crate) virtual_cluster: ::std::option::Option<crate::types::VirtualCluster>,
    _request_id: Option<String>,
}
impl DescribeVirtualClusterOutputBuilder {
    /// <p>This output displays information about the specified virtual cluster.</p>
    pub fn virtual_cluster(mut self, input: crate::types::VirtualCluster) -> Self {
        self.virtual_cluster = ::std::option::Option::Some(input);
        self
    }
    /// <p>This output displays information about the specified virtual cluster.</p>
    pub fn set_virtual_cluster(mut self, input: ::std::option::Option<crate::types::VirtualCluster>) -> Self {
        self.virtual_cluster = input;
        self
    }
    /// <p>This output displays information about the specified virtual cluster.</p>
    pub fn get_virtual_cluster(&self) -> &::std::option::Option<crate::types::VirtualCluster> {
        &self.virtual_cluster
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeVirtualClusterOutput`](crate::operation::describe_virtual_cluster::DescribeVirtualClusterOutput).
    pub fn build(self) -> crate::operation::describe_virtual_cluster::DescribeVirtualClusterOutput {
        crate::operation::describe_virtual_cluster::DescribeVirtualClusterOutput {
            virtual_cluster: self.virtual_cluster,
            _request_id: self._request_id,
        }
    }
}
