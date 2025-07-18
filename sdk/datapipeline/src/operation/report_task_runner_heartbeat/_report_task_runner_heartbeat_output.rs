// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the output of ReportTaskRunnerHeartbeat.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReportTaskRunnerHeartbeatOutput {
    /// <p>Indicates whether the calling task runner should terminate.</p>
    pub terminate: bool,
    _request_id: Option<String>,
}
impl ReportTaskRunnerHeartbeatOutput {
    /// <p>Indicates whether the calling task runner should terminate.</p>
    pub fn terminate(&self) -> bool {
        self.terminate
    }
}
impl ::aws_types::request_id::RequestId for ReportTaskRunnerHeartbeatOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ReportTaskRunnerHeartbeatOutput {
    /// Creates a new builder-style object to manufacture [`ReportTaskRunnerHeartbeatOutput`](crate::operation::report_task_runner_heartbeat::ReportTaskRunnerHeartbeatOutput).
    pub fn builder() -> crate::operation::report_task_runner_heartbeat::builders::ReportTaskRunnerHeartbeatOutputBuilder {
        crate::operation::report_task_runner_heartbeat::builders::ReportTaskRunnerHeartbeatOutputBuilder::default()
    }
}

/// A builder for [`ReportTaskRunnerHeartbeatOutput`](crate::operation::report_task_runner_heartbeat::ReportTaskRunnerHeartbeatOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReportTaskRunnerHeartbeatOutputBuilder {
    pub(crate) terminate: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl ReportTaskRunnerHeartbeatOutputBuilder {
    /// <p>Indicates whether the calling task runner should terminate.</p>
    /// This field is required.
    pub fn terminate(mut self, input: bool) -> Self {
        self.terminate = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the calling task runner should terminate.</p>
    pub fn set_terminate(mut self, input: ::std::option::Option<bool>) -> Self {
        self.terminate = input;
        self
    }
    /// <p>Indicates whether the calling task runner should terminate.</p>
    pub fn get_terminate(&self) -> &::std::option::Option<bool> {
        &self.terminate
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ReportTaskRunnerHeartbeatOutput`](crate::operation::report_task_runner_heartbeat::ReportTaskRunnerHeartbeatOutput).
    pub fn build(self) -> crate::operation::report_task_runner_heartbeat::ReportTaskRunnerHeartbeatOutput {
        crate::operation::report_task_runner_heartbeat::ReportTaskRunnerHeartbeatOutput {
            terminate: self.terminate.unwrap_or_default(),
            _request_id: self._request_id,
        }
    }
}
