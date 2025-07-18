// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopWorkspacesInput {
    /// <p>The WorkSpaces to stop. You can specify up to 25 WorkSpaces.</p>
    pub stop_workspace_requests: ::std::option::Option<::std::vec::Vec<crate::types::StopRequest>>,
}
impl StopWorkspacesInput {
    /// <p>The WorkSpaces to stop. You can specify up to 25 WorkSpaces.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.stop_workspace_requests.is_none()`.
    pub fn stop_workspace_requests(&self) -> &[crate::types::StopRequest] {
        self.stop_workspace_requests.as_deref().unwrap_or_default()
    }
}
impl StopWorkspacesInput {
    /// Creates a new builder-style object to manufacture [`StopWorkspacesInput`](crate::operation::stop_workspaces::StopWorkspacesInput).
    pub fn builder() -> crate::operation::stop_workspaces::builders::StopWorkspacesInputBuilder {
        crate::operation::stop_workspaces::builders::StopWorkspacesInputBuilder::default()
    }
}

/// A builder for [`StopWorkspacesInput`](crate::operation::stop_workspaces::StopWorkspacesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopWorkspacesInputBuilder {
    pub(crate) stop_workspace_requests: ::std::option::Option<::std::vec::Vec<crate::types::StopRequest>>,
}
impl StopWorkspacesInputBuilder {
    /// Appends an item to `stop_workspace_requests`.
    ///
    /// To override the contents of this collection use [`set_stop_workspace_requests`](Self::set_stop_workspace_requests).
    ///
    /// <p>The WorkSpaces to stop. You can specify up to 25 WorkSpaces.</p>
    pub fn stop_workspace_requests(mut self, input: crate::types::StopRequest) -> Self {
        let mut v = self.stop_workspace_requests.unwrap_or_default();
        v.push(input);
        self.stop_workspace_requests = ::std::option::Option::Some(v);
        self
    }
    /// <p>The WorkSpaces to stop. You can specify up to 25 WorkSpaces.</p>
    pub fn set_stop_workspace_requests(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StopRequest>>) -> Self {
        self.stop_workspace_requests = input;
        self
    }
    /// <p>The WorkSpaces to stop. You can specify up to 25 WorkSpaces.</p>
    pub fn get_stop_workspace_requests(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StopRequest>> {
        &self.stop_workspace_requests
    }
    /// Consumes the builder and constructs a [`StopWorkspacesInput`](crate::operation::stop_workspaces::StopWorkspacesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::stop_workspaces::StopWorkspacesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::stop_workspaces::StopWorkspacesInput {
            stop_workspace_requests: self.stop_workspace_requests,
        })
    }
}
