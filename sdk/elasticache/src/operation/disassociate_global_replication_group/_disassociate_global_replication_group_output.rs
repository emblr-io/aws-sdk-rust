// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateGlobalReplicationGroupOutput {
    /// <p>Consists of a primary cluster that accepts writes and an associated secondary cluster that resides in a different Amazon region. The secondary cluster accepts only reads. The primary cluster automatically replicates updates to the secondary cluster.</p>
    /// <ul>
    /// <li>
    /// <p>The <b>GlobalReplicationGroupIdSuffix</b> represents the name of the Global datastore, which is what you use to associate a secondary cluster.</p></li>
    /// </ul>
    pub global_replication_group: ::std::option::Option<crate::types::GlobalReplicationGroup>,
    _request_id: Option<String>,
}
impl DisassociateGlobalReplicationGroupOutput {
    /// <p>Consists of a primary cluster that accepts writes and an associated secondary cluster that resides in a different Amazon region. The secondary cluster accepts only reads. The primary cluster automatically replicates updates to the secondary cluster.</p>
    /// <ul>
    /// <li>
    /// <p>The <b>GlobalReplicationGroupIdSuffix</b> represents the name of the Global datastore, which is what you use to associate a secondary cluster.</p></li>
    /// </ul>
    pub fn global_replication_group(&self) -> ::std::option::Option<&crate::types::GlobalReplicationGroup> {
        self.global_replication_group.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DisassociateGlobalReplicationGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DisassociateGlobalReplicationGroupOutput {
    /// Creates a new builder-style object to manufacture [`DisassociateGlobalReplicationGroupOutput`](crate::operation::disassociate_global_replication_group::DisassociateGlobalReplicationGroupOutput).
    pub fn builder() -> crate::operation::disassociate_global_replication_group::builders::DisassociateGlobalReplicationGroupOutputBuilder {
        crate::operation::disassociate_global_replication_group::builders::DisassociateGlobalReplicationGroupOutputBuilder::default()
    }
}

/// A builder for [`DisassociateGlobalReplicationGroupOutput`](crate::operation::disassociate_global_replication_group::DisassociateGlobalReplicationGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateGlobalReplicationGroupOutputBuilder {
    pub(crate) global_replication_group: ::std::option::Option<crate::types::GlobalReplicationGroup>,
    _request_id: Option<String>,
}
impl DisassociateGlobalReplicationGroupOutputBuilder {
    /// <p>Consists of a primary cluster that accepts writes and an associated secondary cluster that resides in a different Amazon region. The secondary cluster accepts only reads. The primary cluster automatically replicates updates to the secondary cluster.</p>
    /// <ul>
    /// <li>
    /// <p>The <b>GlobalReplicationGroupIdSuffix</b> represents the name of the Global datastore, which is what you use to associate a secondary cluster.</p></li>
    /// </ul>
    pub fn global_replication_group(mut self, input: crate::types::GlobalReplicationGroup) -> Self {
        self.global_replication_group = ::std::option::Option::Some(input);
        self
    }
    /// <p>Consists of a primary cluster that accepts writes and an associated secondary cluster that resides in a different Amazon region. The secondary cluster accepts only reads. The primary cluster automatically replicates updates to the secondary cluster.</p>
    /// <ul>
    /// <li>
    /// <p>The <b>GlobalReplicationGroupIdSuffix</b> represents the name of the Global datastore, which is what you use to associate a secondary cluster.</p></li>
    /// </ul>
    pub fn set_global_replication_group(mut self, input: ::std::option::Option<crate::types::GlobalReplicationGroup>) -> Self {
        self.global_replication_group = input;
        self
    }
    /// <p>Consists of a primary cluster that accepts writes and an associated secondary cluster that resides in a different Amazon region. The secondary cluster accepts only reads. The primary cluster automatically replicates updates to the secondary cluster.</p>
    /// <ul>
    /// <li>
    /// <p>The <b>GlobalReplicationGroupIdSuffix</b> represents the name of the Global datastore, which is what you use to associate a secondary cluster.</p></li>
    /// </ul>
    pub fn get_global_replication_group(&self) -> &::std::option::Option<crate::types::GlobalReplicationGroup> {
        &self.global_replication_group
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DisassociateGlobalReplicationGroupOutput`](crate::operation::disassociate_global_replication_group::DisassociateGlobalReplicationGroupOutput).
    pub fn build(self) -> crate::operation::disassociate_global_replication_group::DisassociateGlobalReplicationGroupOutput {
        crate::operation::disassociate_global_replication_group::DisassociateGlobalReplicationGroupOutput {
            global_replication_group: self.global_replication_group,
            _request_id: self._request_id,
        }
    }
}
