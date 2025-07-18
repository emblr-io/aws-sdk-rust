// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RemoveResourcePermissionOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for RemoveResourcePermissionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RemoveResourcePermissionOutput {
    /// Creates a new builder-style object to manufacture [`RemoveResourcePermissionOutput`](crate::operation::remove_resource_permission::RemoveResourcePermissionOutput).
    pub fn builder() -> crate::operation::remove_resource_permission::builders::RemoveResourcePermissionOutputBuilder {
        crate::operation::remove_resource_permission::builders::RemoveResourcePermissionOutputBuilder::default()
    }
}

/// A builder for [`RemoveResourcePermissionOutput`](crate::operation::remove_resource_permission::RemoveResourcePermissionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RemoveResourcePermissionOutputBuilder {
    _request_id: Option<String>,
}
impl RemoveResourcePermissionOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RemoveResourcePermissionOutput`](crate::operation::remove_resource_permission::RemoveResourcePermissionOutput).
    pub fn build(self) -> crate::operation::remove_resource_permission::RemoveResourcePermissionOutput {
        crate::operation::remove_resource_permission::RemoveResourcePermissionOutput {
            _request_id: self._request_id,
        }
    }
}
