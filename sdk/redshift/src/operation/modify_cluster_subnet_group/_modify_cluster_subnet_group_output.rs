// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyClusterSubnetGroupOutput {
    /// <p>Describes a subnet group.</p>
    pub cluster_subnet_group: ::std::option::Option<crate::types::ClusterSubnetGroup>,
    _request_id: Option<String>,
}
impl ModifyClusterSubnetGroupOutput {
    /// <p>Describes a subnet group.</p>
    pub fn cluster_subnet_group(&self) -> ::std::option::Option<&crate::types::ClusterSubnetGroup> {
        self.cluster_subnet_group.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for ModifyClusterSubnetGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ModifyClusterSubnetGroupOutput {
    /// Creates a new builder-style object to manufacture [`ModifyClusterSubnetGroupOutput`](crate::operation::modify_cluster_subnet_group::ModifyClusterSubnetGroupOutput).
    pub fn builder() -> crate::operation::modify_cluster_subnet_group::builders::ModifyClusterSubnetGroupOutputBuilder {
        crate::operation::modify_cluster_subnet_group::builders::ModifyClusterSubnetGroupOutputBuilder::default()
    }
}

/// A builder for [`ModifyClusterSubnetGroupOutput`](crate::operation::modify_cluster_subnet_group::ModifyClusterSubnetGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyClusterSubnetGroupOutputBuilder {
    pub(crate) cluster_subnet_group: ::std::option::Option<crate::types::ClusterSubnetGroup>,
    _request_id: Option<String>,
}
impl ModifyClusterSubnetGroupOutputBuilder {
    /// <p>Describes a subnet group.</p>
    pub fn cluster_subnet_group(mut self, input: crate::types::ClusterSubnetGroup) -> Self {
        self.cluster_subnet_group = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes a subnet group.</p>
    pub fn set_cluster_subnet_group(mut self, input: ::std::option::Option<crate::types::ClusterSubnetGroup>) -> Self {
        self.cluster_subnet_group = input;
        self
    }
    /// <p>Describes a subnet group.</p>
    pub fn get_cluster_subnet_group(&self) -> &::std::option::Option<crate::types::ClusterSubnetGroup> {
        &self.cluster_subnet_group
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ModifyClusterSubnetGroupOutput`](crate::operation::modify_cluster_subnet_group::ModifyClusterSubnetGroupOutput).
    pub fn build(self) -> crate::operation::modify_cluster_subnet_group::ModifyClusterSubnetGroupOutput {
        crate::operation::modify_cluster_subnet_group::ModifyClusterSubnetGroupOutput {
            cluster_subnet_group: self.cluster_subnet_group,
            _request_id: self._request_id,
        }
    }
}
