// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetMaintenanceWindowExecutionOutput {
    /// <p>The ID of the maintenance window execution.</p>
    pub window_execution_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the task executions from the maintenance window execution.</p>
    pub task_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The status of the maintenance window execution.</p>
    pub status: ::std::option::Option<crate::types::MaintenanceWindowExecutionStatus>,
    /// <p>The details explaining the status. Not available for all status values.</p>
    pub status_details: ::std::option::Option<::std::string::String>,
    /// <p>The time the maintenance window started running.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time the maintenance window finished running.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl GetMaintenanceWindowExecutionOutput {
    /// <p>The ID of the maintenance window execution.</p>
    pub fn window_execution_id(&self) -> ::std::option::Option<&str> {
        self.window_execution_id.as_deref()
    }
    /// <p>The ID of the task executions from the maintenance window execution.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.task_ids.is_none()`.
    pub fn task_ids(&self) -> &[::std::string::String] {
        self.task_ids.as_deref().unwrap_or_default()
    }
    /// <p>The status of the maintenance window execution.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::MaintenanceWindowExecutionStatus> {
        self.status.as_ref()
    }
    /// <p>The details explaining the status. Not available for all status values.</p>
    pub fn status_details(&self) -> ::std::option::Option<&str> {
        self.status_details.as_deref()
    }
    /// <p>The time the maintenance window started running.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The time the maintenance window finished running.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetMaintenanceWindowExecutionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetMaintenanceWindowExecutionOutput {
    /// Creates a new builder-style object to manufacture [`GetMaintenanceWindowExecutionOutput`](crate::operation::get_maintenance_window_execution::GetMaintenanceWindowExecutionOutput).
    pub fn builder() -> crate::operation::get_maintenance_window_execution::builders::GetMaintenanceWindowExecutionOutputBuilder {
        crate::operation::get_maintenance_window_execution::builders::GetMaintenanceWindowExecutionOutputBuilder::default()
    }
}

/// A builder for [`GetMaintenanceWindowExecutionOutput`](crate::operation::get_maintenance_window_execution::GetMaintenanceWindowExecutionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetMaintenanceWindowExecutionOutputBuilder {
    pub(crate) window_execution_id: ::std::option::Option<::std::string::String>,
    pub(crate) task_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) status: ::std::option::Option<crate::types::MaintenanceWindowExecutionStatus>,
    pub(crate) status_details: ::std::option::Option<::std::string::String>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl GetMaintenanceWindowExecutionOutputBuilder {
    /// <p>The ID of the maintenance window execution.</p>
    pub fn window_execution_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.window_execution_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the maintenance window execution.</p>
    pub fn set_window_execution_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.window_execution_id = input;
        self
    }
    /// <p>The ID of the maintenance window execution.</p>
    pub fn get_window_execution_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.window_execution_id
    }
    /// Appends an item to `task_ids`.
    ///
    /// To override the contents of this collection use [`set_task_ids`](Self::set_task_ids).
    ///
    /// <p>The ID of the task executions from the maintenance window execution.</p>
    pub fn task_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.task_ids.unwrap_or_default();
        v.push(input.into());
        self.task_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The ID of the task executions from the maintenance window execution.</p>
    pub fn set_task_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.task_ids = input;
        self
    }
    /// <p>The ID of the task executions from the maintenance window execution.</p>
    pub fn get_task_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.task_ids
    }
    /// <p>The status of the maintenance window execution.</p>
    pub fn status(mut self, input: crate::types::MaintenanceWindowExecutionStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the maintenance window execution.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::MaintenanceWindowExecutionStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the maintenance window execution.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::MaintenanceWindowExecutionStatus> {
        &self.status
    }
    /// <p>The details explaining the status. Not available for all status values.</p>
    pub fn status_details(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_details = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The details explaining the status. Not available for all status values.</p>
    pub fn set_status_details(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_details = input;
        self
    }
    /// <p>The details explaining the status. Not available for all status values.</p>
    pub fn get_status_details(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_details
    }
    /// <p>The time the maintenance window started running.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the maintenance window started running.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The time the maintenance window started running.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The time the maintenance window finished running.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time the maintenance window finished running.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The time the maintenance window finished running.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetMaintenanceWindowExecutionOutput`](crate::operation::get_maintenance_window_execution::GetMaintenanceWindowExecutionOutput).
    pub fn build(self) -> crate::operation::get_maintenance_window_execution::GetMaintenanceWindowExecutionOutput {
        crate::operation::get_maintenance_window_execution::GetMaintenanceWindowExecutionOutput {
            window_execution_id: self.window_execution_id,
            task_ids: self.task_ids,
            status: self.status,
            status_details: self.status_details,
            start_time: self.start_time,
            end_time: self.end_time,
            _request_id: self._request_id,
        }
    }
}
