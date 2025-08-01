// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RemoveRoleFromDbClusterOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for RemoveRoleFromDbClusterOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RemoveRoleFromDbClusterOutput {
    /// Creates a new builder-style object to manufacture [`RemoveRoleFromDbClusterOutput`](crate::operation::remove_role_from_db_cluster::RemoveRoleFromDbClusterOutput).
    pub fn builder() -> crate::operation::remove_role_from_db_cluster::builders::RemoveRoleFromDbClusterOutputBuilder {
        crate::operation::remove_role_from_db_cluster::builders::RemoveRoleFromDbClusterOutputBuilder::default()
    }
}

/// A builder for [`RemoveRoleFromDbClusterOutput`](crate::operation::remove_role_from_db_cluster::RemoveRoleFromDbClusterOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RemoveRoleFromDbClusterOutputBuilder {
    _request_id: Option<String>,
}
impl RemoveRoleFromDbClusterOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RemoveRoleFromDbClusterOutput`](crate::operation::remove_role_from_db_cluster::RemoveRoleFromDbClusterOutput).
    pub fn build(self) -> crate::operation::remove_role_from_db_cluster::RemoveRoleFromDbClusterOutput {
        crate::operation::remove_role_from_db_cluster::RemoveRoleFromDbClusterOutput {
            _request_id: self._request_id,
        }
    }
}
