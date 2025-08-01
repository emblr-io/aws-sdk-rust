// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartImportLabelsTaskRunOutput {
    /// <p>The unique identifier for the task run.</p>
    pub task_run_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartImportLabelsTaskRunOutput {
    /// <p>The unique identifier for the task run.</p>
    pub fn task_run_id(&self) -> ::std::option::Option<&str> {
        self.task_run_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for StartImportLabelsTaskRunOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartImportLabelsTaskRunOutput {
    /// Creates a new builder-style object to manufacture [`StartImportLabelsTaskRunOutput`](crate::operation::start_import_labels_task_run::StartImportLabelsTaskRunOutput).
    pub fn builder() -> crate::operation::start_import_labels_task_run::builders::StartImportLabelsTaskRunOutputBuilder {
        crate::operation::start_import_labels_task_run::builders::StartImportLabelsTaskRunOutputBuilder::default()
    }
}

/// A builder for [`StartImportLabelsTaskRunOutput`](crate::operation::start_import_labels_task_run::StartImportLabelsTaskRunOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartImportLabelsTaskRunOutputBuilder {
    pub(crate) task_run_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartImportLabelsTaskRunOutputBuilder {
    /// <p>The unique identifier for the task run.</p>
    pub fn task_run_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_run_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the task run.</p>
    pub fn set_task_run_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_run_id = input;
        self
    }
    /// <p>The unique identifier for the task run.</p>
    pub fn get_task_run_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_run_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartImportLabelsTaskRunOutput`](crate::operation::start_import_labels_task_run::StartImportLabelsTaskRunOutput).
    pub fn build(self) -> crate::operation::start_import_labels_task_run::StartImportLabelsTaskRunOutput {
        crate::operation::start_import_labels_task_run::StartImportLabelsTaskRunOutput {
            task_run_id: self.task_run_id,
            _request_id: self._request_id,
        }
    }
}
