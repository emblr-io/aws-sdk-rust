// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteContainerPolicyOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteContainerPolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteContainerPolicyOutput {
    /// Creates a new builder-style object to manufacture [`DeleteContainerPolicyOutput`](crate::operation::delete_container_policy::DeleteContainerPolicyOutput).
    pub fn builder() -> crate::operation::delete_container_policy::builders::DeleteContainerPolicyOutputBuilder {
        crate::operation::delete_container_policy::builders::DeleteContainerPolicyOutputBuilder::default()
    }
}

/// A builder for [`DeleteContainerPolicyOutput`](crate::operation::delete_container_policy::DeleteContainerPolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteContainerPolicyOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteContainerPolicyOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteContainerPolicyOutput`](crate::operation::delete_container_policy::DeleteContainerPolicyOutput).
    pub fn build(self) -> crate::operation::delete_container_policy::DeleteContainerPolicyOutput {
        crate::operation::delete_container_policy::DeleteContainerPolicyOutput {
            _request_id: self._request_id,
        }
    }
}
