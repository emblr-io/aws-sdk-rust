// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateWorkspaceServiceAccountInput {
    /// <p>A name for the service account. The name must be unique within the workspace, as it determines the ID associated with the service account.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The permission level to use for this service account.</p><note>
    /// <p>For more information about the roles and the permissions each has, see <a href="https://docs.aws.amazon.com/grafana/latest/userguide/Grafana-user-roles.html">User roles</a> in the <i>Amazon Managed Grafana User Guide</i>.</p>
    /// </note>
    pub grafana_role: ::std::option::Option<crate::types::Role>,
    /// <p>The ID of the workspace within which to create the service account.</p>
    pub workspace_id: ::std::option::Option<::std::string::String>,
}
impl CreateWorkspaceServiceAccountInput {
    /// <p>A name for the service account. The name must be unique within the workspace, as it determines the ID associated with the service account.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The permission level to use for this service account.</p><note>
    /// <p>For more information about the roles and the permissions each has, see <a href="https://docs.aws.amazon.com/grafana/latest/userguide/Grafana-user-roles.html">User roles</a> in the <i>Amazon Managed Grafana User Guide</i>.</p>
    /// </note>
    pub fn grafana_role(&self) -> ::std::option::Option<&crate::types::Role> {
        self.grafana_role.as_ref()
    }
    /// <p>The ID of the workspace within which to create the service account.</p>
    pub fn workspace_id(&self) -> ::std::option::Option<&str> {
        self.workspace_id.as_deref()
    }
}
impl CreateWorkspaceServiceAccountInput {
    /// Creates a new builder-style object to manufacture [`CreateWorkspaceServiceAccountInput`](crate::operation::create_workspace_service_account::CreateWorkspaceServiceAccountInput).
    pub fn builder() -> crate::operation::create_workspace_service_account::builders::CreateWorkspaceServiceAccountInputBuilder {
        crate::operation::create_workspace_service_account::builders::CreateWorkspaceServiceAccountInputBuilder::default()
    }
}

/// A builder for [`CreateWorkspaceServiceAccountInput`](crate::operation::create_workspace_service_account::CreateWorkspaceServiceAccountInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateWorkspaceServiceAccountInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) grafana_role: ::std::option::Option<crate::types::Role>,
    pub(crate) workspace_id: ::std::option::Option<::std::string::String>,
}
impl CreateWorkspaceServiceAccountInputBuilder {
    /// <p>A name for the service account. The name must be unique within the workspace, as it determines the ID associated with the service account.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name for the service account. The name must be unique within the workspace, as it determines the ID associated with the service account.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A name for the service account. The name must be unique within the workspace, as it determines the ID associated with the service account.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The permission level to use for this service account.</p><note>
    /// <p>For more information about the roles and the permissions each has, see <a href="https://docs.aws.amazon.com/grafana/latest/userguide/Grafana-user-roles.html">User roles</a> in the <i>Amazon Managed Grafana User Guide</i>.</p>
    /// </note>
    /// This field is required.
    pub fn grafana_role(mut self, input: crate::types::Role) -> Self {
        self.grafana_role = ::std::option::Option::Some(input);
        self
    }
    /// <p>The permission level to use for this service account.</p><note>
    /// <p>For more information about the roles and the permissions each has, see <a href="https://docs.aws.amazon.com/grafana/latest/userguide/Grafana-user-roles.html">User roles</a> in the <i>Amazon Managed Grafana User Guide</i>.</p>
    /// </note>
    pub fn set_grafana_role(mut self, input: ::std::option::Option<crate::types::Role>) -> Self {
        self.grafana_role = input;
        self
    }
    /// <p>The permission level to use for this service account.</p><note>
    /// <p>For more information about the roles and the permissions each has, see <a href="https://docs.aws.amazon.com/grafana/latest/userguide/Grafana-user-roles.html">User roles</a> in the <i>Amazon Managed Grafana User Guide</i>.</p>
    /// </note>
    pub fn get_grafana_role(&self) -> &::std::option::Option<crate::types::Role> {
        &self.grafana_role
    }
    /// <p>The ID of the workspace within which to create the service account.</p>
    /// This field is required.
    pub fn workspace_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workspace_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the workspace within which to create the service account.</p>
    pub fn set_workspace_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workspace_id = input;
        self
    }
    /// <p>The ID of the workspace within which to create the service account.</p>
    pub fn get_workspace_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workspace_id
    }
    /// Consumes the builder and constructs a [`CreateWorkspaceServiceAccountInput`](crate::operation::create_workspace_service_account::CreateWorkspaceServiceAccountInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_workspace_service_account::CreateWorkspaceServiceAccountInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_workspace_service_account::CreateWorkspaceServiceAccountInput {
            name: self.name,
            grafana_role: self.grafana_role,
            workspace_id: self.workspace_id,
        })
    }
}
