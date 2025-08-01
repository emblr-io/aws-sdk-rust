// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateWorkspaceServiceAccountOutput {
    /// <p>The ID of the service account.</p>
    pub id: ::std::string::String,
    /// <p>The name of the service account.</p>
    pub name: ::std::string::String,
    /// <p>The permission level given to the service account.</p>
    pub grafana_role: crate::types::Role,
    /// <p>The workspace with which the service account is associated.</p>
    pub workspace_id: ::std::string::String,
    _request_id: Option<String>,
}
impl CreateWorkspaceServiceAccountOutput {
    /// <p>The ID of the service account.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The name of the service account.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The permission level given to the service account.</p>
    pub fn grafana_role(&self) -> &crate::types::Role {
        &self.grafana_role
    }
    /// <p>The workspace with which the service account is associated.</p>
    pub fn workspace_id(&self) -> &str {
        use std::ops::Deref;
        self.workspace_id.deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateWorkspaceServiceAccountOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateWorkspaceServiceAccountOutput {
    /// Creates a new builder-style object to manufacture [`CreateWorkspaceServiceAccountOutput`](crate::operation::create_workspace_service_account::CreateWorkspaceServiceAccountOutput).
    pub fn builder() -> crate::operation::create_workspace_service_account::builders::CreateWorkspaceServiceAccountOutputBuilder {
        crate::operation::create_workspace_service_account::builders::CreateWorkspaceServiceAccountOutputBuilder::default()
    }
}

/// A builder for [`CreateWorkspaceServiceAccountOutput`](crate::operation::create_workspace_service_account::CreateWorkspaceServiceAccountOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateWorkspaceServiceAccountOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) grafana_role: ::std::option::Option<crate::types::Role>,
    pub(crate) workspace_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateWorkspaceServiceAccountOutputBuilder {
    /// <p>The ID of the service account.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the service account.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the service account.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name of the service account.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the service account.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the service account.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The permission level given to the service account.</p>
    /// This field is required.
    pub fn grafana_role(mut self, input: crate::types::Role) -> Self {
        self.grafana_role = ::std::option::Option::Some(input);
        self
    }
    /// <p>The permission level given to the service account.</p>
    pub fn set_grafana_role(mut self, input: ::std::option::Option<crate::types::Role>) -> Self {
        self.grafana_role = input;
        self
    }
    /// <p>The permission level given to the service account.</p>
    pub fn get_grafana_role(&self) -> &::std::option::Option<crate::types::Role> {
        &self.grafana_role
    }
    /// <p>The workspace with which the service account is associated.</p>
    /// This field is required.
    pub fn workspace_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workspace_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The workspace with which the service account is associated.</p>
    pub fn set_workspace_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workspace_id = input;
        self
    }
    /// <p>The workspace with which the service account is associated.</p>
    pub fn get_workspace_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workspace_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateWorkspaceServiceAccountOutput`](crate::operation::create_workspace_service_account::CreateWorkspaceServiceAccountOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::operation::create_workspace_service_account::builders::CreateWorkspaceServiceAccountOutputBuilder::id)
    /// - [`name`](crate::operation::create_workspace_service_account::builders::CreateWorkspaceServiceAccountOutputBuilder::name)
    /// - [`grafana_role`](crate::operation::create_workspace_service_account::builders::CreateWorkspaceServiceAccountOutputBuilder::grafana_role)
    /// - [`workspace_id`](crate::operation::create_workspace_service_account::builders::CreateWorkspaceServiceAccountOutputBuilder::workspace_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_workspace_service_account::CreateWorkspaceServiceAccountOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_workspace_service_account::CreateWorkspaceServiceAccountOutput {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building CreateWorkspaceServiceAccountOutput",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building CreateWorkspaceServiceAccountOutput",
                )
            })?,
            grafana_role: self.grafana_role.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "grafana_role",
                    "grafana_role was not specified but it is required when building CreateWorkspaceServiceAccountOutput",
                )
            })?,
            workspace_id: self.workspace_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "workspace_id",
                    "workspace_id was not specified but it is required when building CreateWorkspaceServiceAccountOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
