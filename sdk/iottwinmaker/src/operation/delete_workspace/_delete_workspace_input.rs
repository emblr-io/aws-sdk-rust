// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteWorkspaceInput {
    /// <p>The ID of the workspace to delete.</p>
    pub workspace_id: ::std::option::Option<::std::string::String>,
}
impl DeleteWorkspaceInput {
    /// <p>The ID of the workspace to delete.</p>
    pub fn workspace_id(&self) -> ::std::option::Option<&str> {
        self.workspace_id.as_deref()
    }
}
impl DeleteWorkspaceInput {
    /// Creates a new builder-style object to manufacture [`DeleteWorkspaceInput`](crate::operation::delete_workspace::DeleteWorkspaceInput).
    pub fn builder() -> crate::operation::delete_workspace::builders::DeleteWorkspaceInputBuilder {
        crate::operation::delete_workspace::builders::DeleteWorkspaceInputBuilder::default()
    }
}

/// A builder for [`DeleteWorkspaceInput`](crate::operation::delete_workspace::DeleteWorkspaceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteWorkspaceInputBuilder {
    pub(crate) workspace_id: ::std::option::Option<::std::string::String>,
}
impl DeleteWorkspaceInputBuilder {
    /// <p>The ID of the workspace to delete.</p>
    /// This field is required.
    pub fn workspace_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workspace_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the workspace to delete.</p>
    pub fn set_workspace_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workspace_id = input;
        self
    }
    /// <p>The ID of the workspace to delete.</p>
    pub fn get_workspace_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workspace_id
    }
    /// Consumes the builder and constructs a [`DeleteWorkspaceInput`](crate::operation::delete_workspace::DeleteWorkspaceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_workspace::DeleteWorkspaceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_workspace::DeleteWorkspaceInput {
            workspace_id: self.workspace_id,
        })
    }
}
