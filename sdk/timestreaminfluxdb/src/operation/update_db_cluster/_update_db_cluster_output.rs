// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDbClusterOutput {
    /// <p>The status of the DB cluster.</p>
    pub db_cluster_status: ::std::option::Option<crate::types::ClusterStatus>,
    _request_id: Option<String>,
}
impl UpdateDbClusterOutput {
    /// <p>The status of the DB cluster.</p>
    pub fn db_cluster_status(&self) -> ::std::option::Option<&crate::types::ClusterStatus> {
        self.db_cluster_status.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateDbClusterOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateDbClusterOutput {
    /// Creates a new builder-style object to manufacture [`UpdateDbClusterOutput`](crate::operation::update_db_cluster::UpdateDbClusterOutput).
    pub fn builder() -> crate::operation::update_db_cluster::builders::UpdateDbClusterOutputBuilder {
        crate::operation::update_db_cluster::builders::UpdateDbClusterOutputBuilder::default()
    }
}

/// A builder for [`UpdateDbClusterOutput`](crate::operation::update_db_cluster::UpdateDbClusterOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDbClusterOutputBuilder {
    pub(crate) db_cluster_status: ::std::option::Option<crate::types::ClusterStatus>,
    _request_id: Option<String>,
}
impl UpdateDbClusterOutputBuilder {
    /// <p>The status of the DB cluster.</p>
    pub fn db_cluster_status(mut self, input: crate::types::ClusterStatus) -> Self {
        self.db_cluster_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the DB cluster.</p>
    pub fn set_db_cluster_status(mut self, input: ::std::option::Option<crate::types::ClusterStatus>) -> Self {
        self.db_cluster_status = input;
        self
    }
    /// <p>The status of the DB cluster.</p>
    pub fn get_db_cluster_status(&self) -> &::std::option::Option<crate::types::ClusterStatus> {
        &self.db_cluster_status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateDbClusterOutput`](crate::operation::update_db_cluster::UpdateDbClusterOutput).
    pub fn build(self) -> crate::operation::update_db_cluster::UpdateDbClusterOutput {
        crate::operation::update_db_cluster::UpdateDbClusterOutput {
            db_cluster_status: self.db_cluster_status,
            _request_id: self._request_id,
        }
    }
}
