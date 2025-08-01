// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyWorkspaceCreationPropertiesOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for ModifyWorkspaceCreationPropertiesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ModifyWorkspaceCreationPropertiesOutput {
    /// Creates a new builder-style object to manufacture [`ModifyWorkspaceCreationPropertiesOutput`](crate::operation::modify_workspace_creation_properties::ModifyWorkspaceCreationPropertiesOutput).
    pub fn builder() -> crate::operation::modify_workspace_creation_properties::builders::ModifyWorkspaceCreationPropertiesOutputBuilder {
        crate::operation::modify_workspace_creation_properties::builders::ModifyWorkspaceCreationPropertiesOutputBuilder::default()
    }
}

/// A builder for [`ModifyWorkspaceCreationPropertiesOutput`](crate::operation::modify_workspace_creation_properties::ModifyWorkspaceCreationPropertiesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyWorkspaceCreationPropertiesOutputBuilder {
    _request_id: Option<String>,
}
impl ModifyWorkspaceCreationPropertiesOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ModifyWorkspaceCreationPropertiesOutput`](crate::operation::modify_workspace_creation_properties::ModifyWorkspaceCreationPropertiesOutput).
    pub fn build(self) -> crate::operation::modify_workspace_creation_properties::ModifyWorkspaceCreationPropertiesOutput {
        crate::operation::modify_workspace_creation_properties::ModifyWorkspaceCreationPropertiesOutput {
            _request_id: self._request_id,
        }
    }
}
