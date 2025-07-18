// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyWorkspacePropertiesOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for ModifyWorkspacePropertiesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ModifyWorkspacePropertiesOutput {
    /// Creates a new builder-style object to manufacture [`ModifyWorkspacePropertiesOutput`](crate::operation::modify_workspace_properties::ModifyWorkspacePropertiesOutput).
    pub fn builder() -> crate::operation::modify_workspace_properties::builders::ModifyWorkspacePropertiesOutputBuilder {
        crate::operation::modify_workspace_properties::builders::ModifyWorkspacePropertiesOutputBuilder::default()
    }
}

/// A builder for [`ModifyWorkspacePropertiesOutput`](crate::operation::modify_workspace_properties::ModifyWorkspacePropertiesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyWorkspacePropertiesOutputBuilder {
    _request_id: Option<String>,
}
impl ModifyWorkspacePropertiesOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ModifyWorkspacePropertiesOutput`](crate::operation::modify_workspace_properties::ModifyWorkspacePropertiesOutput).
    pub fn build(self) -> crate::operation::modify_workspace_properties::ModifyWorkspacePropertiesOutput {
        crate::operation::modify_workspace_properties::ModifyWorkspacePropertiesOutput {
            _request_id: self._request_id,
        }
    }
}
