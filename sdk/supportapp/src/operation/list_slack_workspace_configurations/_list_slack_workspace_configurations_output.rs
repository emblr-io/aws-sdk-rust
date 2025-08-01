// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSlackWorkspaceConfigurationsOutput {
    /// <p>The point where pagination should resume when the response returns only partial results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The configurations for a Slack workspace.</p>
    pub slack_workspace_configurations: ::std::option::Option<::std::vec::Vec<crate::types::SlackWorkspaceConfiguration>>,
    _request_id: Option<String>,
}
impl ListSlackWorkspaceConfigurationsOutput {
    /// <p>The point where pagination should resume when the response returns only partial results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The configurations for a Slack workspace.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.slack_workspace_configurations.is_none()`.
    pub fn slack_workspace_configurations(&self) -> &[crate::types::SlackWorkspaceConfiguration] {
        self.slack_workspace_configurations.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListSlackWorkspaceConfigurationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListSlackWorkspaceConfigurationsOutput {
    /// Creates a new builder-style object to manufacture [`ListSlackWorkspaceConfigurationsOutput`](crate::operation::list_slack_workspace_configurations::ListSlackWorkspaceConfigurationsOutput).
    pub fn builder() -> crate::operation::list_slack_workspace_configurations::builders::ListSlackWorkspaceConfigurationsOutputBuilder {
        crate::operation::list_slack_workspace_configurations::builders::ListSlackWorkspaceConfigurationsOutputBuilder::default()
    }
}

/// A builder for [`ListSlackWorkspaceConfigurationsOutput`](crate::operation::list_slack_workspace_configurations::ListSlackWorkspaceConfigurationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSlackWorkspaceConfigurationsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) slack_workspace_configurations: ::std::option::Option<::std::vec::Vec<crate::types::SlackWorkspaceConfiguration>>,
    _request_id: Option<String>,
}
impl ListSlackWorkspaceConfigurationsOutputBuilder {
    /// <p>The point where pagination should resume when the response returns only partial results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The point where pagination should resume when the response returns only partial results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The point where pagination should resume when the response returns only partial results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `slack_workspace_configurations`.
    ///
    /// To override the contents of this collection use [`set_slack_workspace_configurations`](Self::set_slack_workspace_configurations).
    ///
    /// <p>The configurations for a Slack workspace.</p>
    pub fn slack_workspace_configurations(mut self, input: crate::types::SlackWorkspaceConfiguration) -> Self {
        let mut v = self.slack_workspace_configurations.unwrap_or_default();
        v.push(input);
        self.slack_workspace_configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The configurations for a Slack workspace.</p>
    pub fn set_slack_workspace_configurations(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::SlackWorkspaceConfiguration>>,
    ) -> Self {
        self.slack_workspace_configurations = input;
        self
    }
    /// <p>The configurations for a Slack workspace.</p>
    pub fn get_slack_workspace_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SlackWorkspaceConfiguration>> {
        &self.slack_workspace_configurations
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListSlackWorkspaceConfigurationsOutput`](crate::operation::list_slack_workspace_configurations::ListSlackWorkspaceConfigurationsOutput).
    pub fn build(self) -> crate::operation::list_slack_workspace_configurations::ListSlackWorkspaceConfigurationsOutput {
        crate::operation::list_slack_workspace_configurations::ListSlackWorkspaceConfigurationsOutput {
            next_token: self.next_token,
            slack_workspace_configurations: self.slack_workspace_configurations,
            _request_id: self._request_id,
        }
    }
}
