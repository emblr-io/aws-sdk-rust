// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetCommandExecutionsOutput {
    /// <p>Information about the requested command executions.</p>
    pub command_executions: ::std::option::Option<::std::vec::Vec<crate::types::CommandExecution>>,
    /// <p>The IDs of command executions for which information could not be found.</p>
    pub command_executions_not_found: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl BatchGetCommandExecutionsOutput {
    /// <p>Information about the requested command executions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.command_executions.is_none()`.
    pub fn command_executions(&self) -> &[crate::types::CommandExecution] {
        self.command_executions.as_deref().unwrap_or_default()
    }
    /// <p>The IDs of command executions for which information could not be found.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.command_executions_not_found.is_none()`.
    pub fn command_executions_not_found(&self) -> &[::std::string::String] {
        self.command_executions_not_found.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for BatchGetCommandExecutionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchGetCommandExecutionsOutput {
    /// Creates a new builder-style object to manufacture [`BatchGetCommandExecutionsOutput`](crate::operation::batch_get_command_executions::BatchGetCommandExecutionsOutput).
    pub fn builder() -> crate::operation::batch_get_command_executions::builders::BatchGetCommandExecutionsOutputBuilder {
        crate::operation::batch_get_command_executions::builders::BatchGetCommandExecutionsOutputBuilder::default()
    }
}

/// A builder for [`BatchGetCommandExecutionsOutput`](crate::operation::batch_get_command_executions::BatchGetCommandExecutionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetCommandExecutionsOutputBuilder {
    pub(crate) command_executions: ::std::option::Option<::std::vec::Vec<crate::types::CommandExecution>>,
    pub(crate) command_executions_not_found: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl BatchGetCommandExecutionsOutputBuilder {
    /// Appends an item to `command_executions`.
    ///
    /// To override the contents of this collection use [`set_command_executions`](Self::set_command_executions).
    ///
    /// <p>Information about the requested command executions.</p>
    pub fn command_executions(mut self, input: crate::types::CommandExecution) -> Self {
        let mut v = self.command_executions.unwrap_or_default();
        v.push(input);
        self.command_executions = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the requested command executions.</p>
    pub fn set_command_executions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CommandExecution>>) -> Self {
        self.command_executions = input;
        self
    }
    /// <p>Information about the requested command executions.</p>
    pub fn get_command_executions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CommandExecution>> {
        &self.command_executions
    }
    /// Appends an item to `command_executions_not_found`.
    ///
    /// To override the contents of this collection use [`set_command_executions_not_found`](Self::set_command_executions_not_found).
    ///
    /// <p>The IDs of command executions for which information could not be found.</p>
    pub fn command_executions_not_found(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.command_executions_not_found.unwrap_or_default();
        v.push(input.into());
        self.command_executions_not_found = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of command executions for which information could not be found.</p>
    pub fn set_command_executions_not_found(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.command_executions_not_found = input;
        self
    }
    /// <p>The IDs of command executions for which information could not be found.</p>
    pub fn get_command_executions_not_found(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.command_executions_not_found
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`BatchGetCommandExecutionsOutput`](crate::operation::batch_get_command_executions::BatchGetCommandExecutionsOutput).
    pub fn build(self) -> crate::operation::batch_get_command_executions::BatchGetCommandExecutionsOutput {
        crate::operation::batch_get_command_executions::BatchGetCommandExecutionsOutput {
            command_executions: self.command_executions,
            command_executions_not_found: self.command_executions_not_found,
            _request_id: self._request_id,
        }
    }
}
