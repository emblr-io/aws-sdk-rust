// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DecreaseReplicationFactorOutput {
    /// <p>A description of the DAX cluster, after you have decreased its replication factor.</p>
    pub cluster: ::std::option::Option<crate::types::Cluster>,
    _request_id: Option<String>,
}
impl DecreaseReplicationFactorOutput {
    /// <p>A description of the DAX cluster, after you have decreased its replication factor.</p>
    pub fn cluster(&self) -> ::std::option::Option<&crate::types::Cluster> {
        self.cluster.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DecreaseReplicationFactorOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DecreaseReplicationFactorOutput {
    /// Creates a new builder-style object to manufacture [`DecreaseReplicationFactorOutput`](crate::operation::decrease_replication_factor::DecreaseReplicationFactorOutput).
    pub fn builder() -> crate::operation::decrease_replication_factor::builders::DecreaseReplicationFactorOutputBuilder {
        crate::operation::decrease_replication_factor::builders::DecreaseReplicationFactorOutputBuilder::default()
    }
}

/// A builder for [`DecreaseReplicationFactorOutput`](crate::operation::decrease_replication_factor::DecreaseReplicationFactorOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DecreaseReplicationFactorOutputBuilder {
    pub(crate) cluster: ::std::option::Option<crate::types::Cluster>,
    _request_id: Option<String>,
}
impl DecreaseReplicationFactorOutputBuilder {
    /// <p>A description of the DAX cluster, after you have decreased its replication factor.</p>
    pub fn cluster(mut self, input: crate::types::Cluster) -> Self {
        self.cluster = ::std::option::Option::Some(input);
        self
    }
    /// <p>A description of the DAX cluster, after you have decreased its replication factor.</p>
    pub fn set_cluster(mut self, input: ::std::option::Option<crate::types::Cluster>) -> Self {
        self.cluster = input;
        self
    }
    /// <p>A description of the DAX cluster, after you have decreased its replication factor.</p>
    pub fn get_cluster(&self) -> &::std::option::Option<crate::types::Cluster> {
        &self.cluster
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DecreaseReplicationFactorOutput`](crate::operation::decrease_replication_factor::DecreaseReplicationFactorOutput).
    pub fn build(self) -> crate::operation::decrease_replication_factor::DecreaseReplicationFactorOutput {
        crate::operation::decrease_replication_factor::DecreaseReplicationFactorOutput {
            cluster: self.cluster,
            _request_id: self._request_id,
        }
    }
}
