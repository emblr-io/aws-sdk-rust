// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelImportTaskOutput {
    /// <p>The ID of the task being canceled.</p>
    pub import_task_id: ::std::option::Option<::std::string::String>,
    /// <p>The current state of the task being canceled.</p>
    pub previous_state: ::std::option::Option<::std::string::String>,
    /// <p>The current state of the task being canceled.</p>
    pub state: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CancelImportTaskOutput {
    /// <p>The ID of the task being canceled.</p>
    pub fn import_task_id(&self) -> ::std::option::Option<&str> {
        self.import_task_id.as_deref()
    }
    /// <p>The current state of the task being canceled.</p>
    pub fn previous_state(&self) -> ::std::option::Option<&str> {
        self.previous_state.as_deref()
    }
    /// <p>The current state of the task being canceled.</p>
    pub fn state(&self) -> ::std::option::Option<&str> {
        self.state.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CancelImportTaskOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CancelImportTaskOutput {
    /// Creates a new builder-style object to manufacture [`CancelImportTaskOutput`](crate::operation::cancel_import_task::CancelImportTaskOutput).
    pub fn builder() -> crate::operation::cancel_import_task::builders::CancelImportTaskOutputBuilder {
        crate::operation::cancel_import_task::builders::CancelImportTaskOutputBuilder::default()
    }
}

/// A builder for [`CancelImportTaskOutput`](crate::operation::cancel_import_task::CancelImportTaskOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelImportTaskOutputBuilder {
    pub(crate) import_task_id: ::std::option::Option<::std::string::String>,
    pub(crate) previous_state: ::std::option::Option<::std::string::String>,
    pub(crate) state: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CancelImportTaskOutputBuilder {
    /// <p>The ID of the task being canceled.</p>
    pub fn import_task_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.import_task_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the task being canceled.</p>
    pub fn set_import_task_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.import_task_id = input;
        self
    }
    /// <p>The ID of the task being canceled.</p>
    pub fn get_import_task_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.import_task_id
    }
    /// <p>The current state of the task being canceled.</p>
    pub fn previous_state(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.previous_state = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current state of the task being canceled.</p>
    pub fn set_previous_state(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.previous_state = input;
        self
    }
    /// <p>The current state of the task being canceled.</p>
    pub fn get_previous_state(&self) -> &::std::option::Option<::std::string::String> {
        &self.previous_state
    }
    /// <p>The current state of the task being canceled.</p>
    pub fn state(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.state = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current state of the task being canceled.</p>
    pub fn set_state(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.state = input;
        self
    }
    /// <p>The current state of the task being canceled.</p>
    pub fn get_state(&self) -> &::std::option::Option<::std::string::String> {
        &self.state
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CancelImportTaskOutput`](crate::operation::cancel_import_task::CancelImportTaskOutput).
    pub fn build(self) -> crate::operation::cancel_import_task::CancelImportTaskOutput {
        crate::operation::cancel_import_task::CancelImportTaskOutput {
            import_task_id: self.import_task_id,
            previous_state: self.previous_state,
            state: self.state,
            _request_id: self._request_id,
        }
    }
}
