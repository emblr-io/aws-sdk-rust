// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyReplicationSubnetGroupOutput {
    /// <p>The modified replication subnet group.</p>
    pub replication_subnet_group: ::std::option::Option<crate::types::ReplicationSubnetGroup>,
    _request_id: Option<String>,
}
impl ModifyReplicationSubnetGroupOutput {
    /// <p>The modified replication subnet group.</p>
    pub fn replication_subnet_group(&self) -> ::std::option::Option<&crate::types::ReplicationSubnetGroup> {
        self.replication_subnet_group.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for ModifyReplicationSubnetGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ModifyReplicationSubnetGroupOutput {
    /// Creates a new builder-style object to manufacture [`ModifyReplicationSubnetGroupOutput`](crate::operation::modify_replication_subnet_group::ModifyReplicationSubnetGroupOutput).
    pub fn builder() -> crate::operation::modify_replication_subnet_group::builders::ModifyReplicationSubnetGroupOutputBuilder {
        crate::operation::modify_replication_subnet_group::builders::ModifyReplicationSubnetGroupOutputBuilder::default()
    }
}

/// A builder for [`ModifyReplicationSubnetGroupOutput`](crate::operation::modify_replication_subnet_group::ModifyReplicationSubnetGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyReplicationSubnetGroupOutputBuilder {
    pub(crate) replication_subnet_group: ::std::option::Option<crate::types::ReplicationSubnetGroup>,
    _request_id: Option<String>,
}
impl ModifyReplicationSubnetGroupOutputBuilder {
    /// <p>The modified replication subnet group.</p>
    pub fn replication_subnet_group(mut self, input: crate::types::ReplicationSubnetGroup) -> Self {
        self.replication_subnet_group = ::std::option::Option::Some(input);
        self
    }
    /// <p>The modified replication subnet group.</p>
    pub fn set_replication_subnet_group(mut self, input: ::std::option::Option<crate::types::ReplicationSubnetGroup>) -> Self {
        self.replication_subnet_group = input;
        self
    }
    /// <p>The modified replication subnet group.</p>
    pub fn get_replication_subnet_group(&self) -> &::std::option::Option<crate::types::ReplicationSubnetGroup> {
        &self.replication_subnet_group
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ModifyReplicationSubnetGroupOutput`](crate::operation::modify_replication_subnet_group::ModifyReplicationSubnetGroupOutput).
    pub fn build(self) -> crate::operation::modify_replication_subnet_group::ModifyReplicationSubnetGroupOutput {
        crate::operation::modify_replication_subnet_group::ModifyReplicationSubnetGroupOutput {
            replication_subnet_group: self.replication_subnet_group,
            _request_id: self._request_id,
        }
    }
}
