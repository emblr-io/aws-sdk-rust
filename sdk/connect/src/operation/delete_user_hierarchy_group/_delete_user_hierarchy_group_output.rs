// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteUserHierarchyGroupOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteUserHierarchyGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteUserHierarchyGroupOutput {
    /// Creates a new builder-style object to manufacture [`DeleteUserHierarchyGroupOutput`](crate::operation::delete_user_hierarchy_group::DeleteUserHierarchyGroupOutput).
    pub fn builder() -> crate::operation::delete_user_hierarchy_group::builders::DeleteUserHierarchyGroupOutputBuilder {
        crate::operation::delete_user_hierarchy_group::builders::DeleteUserHierarchyGroupOutputBuilder::default()
    }
}

/// A builder for [`DeleteUserHierarchyGroupOutput`](crate::operation::delete_user_hierarchy_group::DeleteUserHierarchyGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteUserHierarchyGroupOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteUserHierarchyGroupOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteUserHierarchyGroupOutput`](crate::operation::delete_user_hierarchy_group::DeleteUserHierarchyGroupOutput).
    pub fn build(self) -> crate::operation::delete_user_hierarchy_group::DeleteUserHierarchyGroupOutput {
        crate::operation::delete_user_hierarchy_group::DeleteUserHierarchyGroupOutput {
            _request_id: self._request_id,
        }
    }
}
