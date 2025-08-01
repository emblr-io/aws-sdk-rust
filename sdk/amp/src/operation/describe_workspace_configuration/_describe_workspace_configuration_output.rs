// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeWorkspaceConfigurationOutput {
    /// <p>This structure contains the information about the workspace configuration.</p>
    pub workspace_configuration: ::std::option::Option<crate::types::WorkspaceConfigurationDescription>,
    _request_id: Option<String>,
}
impl DescribeWorkspaceConfigurationOutput {
    /// <p>This structure contains the information about the workspace configuration.</p>
    pub fn workspace_configuration(&self) -> ::std::option::Option<&crate::types::WorkspaceConfigurationDescription> {
        self.workspace_configuration.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeWorkspaceConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeWorkspaceConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`DescribeWorkspaceConfigurationOutput`](crate::operation::describe_workspace_configuration::DescribeWorkspaceConfigurationOutput).
    pub fn builder() -> crate::operation::describe_workspace_configuration::builders::DescribeWorkspaceConfigurationOutputBuilder {
        crate::operation::describe_workspace_configuration::builders::DescribeWorkspaceConfigurationOutputBuilder::default()
    }
}

/// A builder for [`DescribeWorkspaceConfigurationOutput`](crate::operation::describe_workspace_configuration::DescribeWorkspaceConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeWorkspaceConfigurationOutputBuilder {
    pub(crate) workspace_configuration: ::std::option::Option<crate::types::WorkspaceConfigurationDescription>,
    _request_id: Option<String>,
}
impl DescribeWorkspaceConfigurationOutputBuilder {
    /// <p>This structure contains the information about the workspace configuration.</p>
    /// This field is required.
    pub fn workspace_configuration(mut self, input: crate::types::WorkspaceConfigurationDescription) -> Self {
        self.workspace_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>This structure contains the information about the workspace configuration.</p>
    pub fn set_workspace_configuration(mut self, input: ::std::option::Option<crate::types::WorkspaceConfigurationDescription>) -> Self {
        self.workspace_configuration = input;
        self
    }
    /// <p>This structure contains the information about the workspace configuration.</p>
    pub fn get_workspace_configuration(&self) -> &::std::option::Option<crate::types::WorkspaceConfigurationDescription> {
        &self.workspace_configuration
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeWorkspaceConfigurationOutput`](crate::operation::describe_workspace_configuration::DescribeWorkspaceConfigurationOutput).
    pub fn build(self) -> crate::operation::describe_workspace_configuration::DescribeWorkspaceConfigurationOutput {
        crate::operation::describe_workspace_configuration::DescribeWorkspaceConfigurationOutput {
            workspace_configuration: self.workspace_configuration,
            _request_id: self._request_id,
        }
    }
}
