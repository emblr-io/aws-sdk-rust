// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details for a notebook execution. The details include information such as the unique ID and status of the notebook execution.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NotebookExecutionSummary {
    /// <p>The unique identifier of the notebook execution.</p>
    pub notebook_execution_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the editor associated with the notebook execution.</p>
    pub editor_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the notebook execution.</p>
    pub notebook_execution_name: ::std::option::Option<::std::string::String>,
    /// <p>The status of the notebook execution.</p>
    /// <ul>
    /// <li>
    /// <p><code>START_PENDING</code> indicates that the cluster has received the execution request but execution has not begun.</p></li>
    /// <li>
    /// <p><code>STARTING</code> indicates that the execution is starting on the cluster.</p></li>
    /// <li>
    /// <p><code>RUNNING</code> indicates that the execution is being processed by the cluster.</p></li>
    /// <li>
    /// <p><code>FINISHING</code> indicates that execution processing is in the final stages.</p></li>
    /// <li>
    /// <p><code>FINISHED</code> indicates that the execution has completed without error.</p></li>
    /// <li>
    /// <p><code>FAILING</code> indicates that the execution is failing and will not finish successfully.</p></li>
    /// <li>
    /// <p><code>FAILED</code> indicates that the execution failed.</p></li>
    /// <li>
    /// <p><code>STOP_PENDING</code> indicates that the cluster has received a <code>StopNotebookExecution</code> request and the stop is pending.</p></li>
    /// <li>
    /// <p><code>STOPPING</code> indicates that the cluster is in the process of stopping the execution as a result of a <code>StopNotebookExecution</code> request.</p></li>
    /// <li>
    /// <p><code>STOPPED</code> indicates that the execution stopped because of a <code>StopNotebookExecution</code> request.</p></li>
    /// </ul>
    pub status: ::std::option::Option<crate::types::NotebookExecutionStatus>,
    /// <p>The timestamp when notebook execution started.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp when notebook execution started.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Amazon S3 location that stores the notebook execution input.</p>
    pub notebook_s3_location: ::std::option::Option<crate::types::NotebookS3LocationForOutput>,
    /// <p>The unique ID of the execution engine for the notebook execution.</p>
    pub execution_engine_id: ::std::option::Option<::std::string::String>,
}
impl NotebookExecutionSummary {
    /// <p>The unique identifier of the notebook execution.</p>
    pub fn notebook_execution_id(&self) -> ::std::option::Option<&str> {
        self.notebook_execution_id.as_deref()
    }
    /// <p>The unique identifier of the editor associated with the notebook execution.</p>
    pub fn editor_id(&self) -> ::std::option::Option<&str> {
        self.editor_id.as_deref()
    }
    /// <p>The name of the notebook execution.</p>
    pub fn notebook_execution_name(&self) -> ::std::option::Option<&str> {
        self.notebook_execution_name.as_deref()
    }
    /// <p>The status of the notebook execution.</p>
    /// <ul>
    /// <li>
    /// <p><code>START_PENDING</code> indicates that the cluster has received the execution request but execution has not begun.</p></li>
    /// <li>
    /// <p><code>STARTING</code> indicates that the execution is starting on the cluster.</p></li>
    /// <li>
    /// <p><code>RUNNING</code> indicates that the execution is being processed by the cluster.</p></li>
    /// <li>
    /// <p><code>FINISHING</code> indicates that execution processing is in the final stages.</p></li>
    /// <li>
    /// <p><code>FINISHED</code> indicates that the execution has completed without error.</p></li>
    /// <li>
    /// <p><code>FAILING</code> indicates that the execution is failing and will not finish successfully.</p></li>
    /// <li>
    /// <p><code>FAILED</code> indicates that the execution failed.</p></li>
    /// <li>
    /// <p><code>STOP_PENDING</code> indicates that the cluster has received a <code>StopNotebookExecution</code> request and the stop is pending.</p></li>
    /// <li>
    /// <p><code>STOPPING</code> indicates that the cluster is in the process of stopping the execution as a result of a <code>StopNotebookExecution</code> request.</p></li>
    /// <li>
    /// <p><code>STOPPED</code> indicates that the execution stopped because of a <code>StopNotebookExecution</code> request.</p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&crate::types::NotebookExecutionStatus> {
        self.status.as_ref()
    }
    /// <p>The timestamp when notebook execution started.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The timestamp when notebook execution started.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
    /// <p>The Amazon S3 location that stores the notebook execution input.</p>
    pub fn notebook_s3_location(&self) -> ::std::option::Option<&crate::types::NotebookS3LocationForOutput> {
        self.notebook_s3_location.as_ref()
    }
    /// <p>The unique ID of the execution engine for the notebook execution.</p>
    pub fn execution_engine_id(&self) -> ::std::option::Option<&str> {
        self.execution_engine_id.as_deref()
    }
}
impl NotebookExecutionSummary {
    /// Creates a new builder-style object to manufacture [`NotebookExecutionSummary`](crate::types::NotebookExecutionSummary).
    pub fn builder() -> crate::types::builders::NotebookExecutionSummaryBuilder {
        crate::types::builders::NotebookExecutionSummaryBuilder::default()
    }
}

/// A builder for [`NotebookExecutionSummary`](crate::types::NotebookExecutionSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NotebookExecutionSummaryBuilder {
    pub(crate) notebook_execution_id: ::std::option::Option<::std::string::String>,
    pub(crate) editor_id: ::std::option::Option<::std::string::String>,
    pub(crate) notebook_execution_name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::NotebookExecutionStatus>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) notebook_s3_location: ::std::option::Option<crate::types::NotebookS3LocationForOutput>,
    pub(crate) execution_engine_id: ::std::option::Option<::std::string::String>,
}
impl NotebookExecutionSummaryBuilder {
    /// <p>The unique identifier of the notebook execution.</p>
    pub fn notebook_execution_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.notebook_execution_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the notebook execution.</p>
    pub fn set_notebook_execution_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.notebook_execution_id = input;
        self
    }
    /// <p>The unique identifier of the notebook execution.</p>
    pub fn get_notebook_execution_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.notebook_execution_id
    }
    /// <p>The unique identifier of the editor associated with the notebook execution.</p>
    pub fn editor_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.editor_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the editor associated with the notebook execution.</p>
    pub fn set_editor_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.editor_id = input;
        self
    }
    /// <p>The unique identifier of the editor associated with the notebook execution.</p>
    pub fn get_editor_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.editor_id
    }
    /// <p>The name of the notebook execution.</p>
    pub fn notebook_execution_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.notebook_execution_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the notebook execution.</p>
    pub fn set_notebook_execution_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.notebook_execution_name = input;
        self
    }
    /// <p>The name of the notebook execution.</p>
    pub fn get_notebook_execution_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.notebook_execution_name
    }
    /// <p>The status of the notebook execution.</p>
    /// <ul>
    /// <li>
    /// <p><code>START_PENDING</code> indicates that the cluster has received the execution request but execution has not begun.</p></li>
    /// <li>
    /// <p><code>STARTING</code> indicates that the execution is starting on the cluster.</p></li>
    /// <li>
    /// <p><code>RUNNING</code> indicates that the execution is being processed by the cluster.</p></li>
    /// <li>
    /// <p><code>FINISHING</code> indicates that execution processing is in the final stages.</p></li>
    /// <li>
    /// <p><code>FINISHED</code> indicates that the execution has completed without error.</p></li>
    /// <li>
    /// <p><code>FAILING</code> indicates that the execution is failing and will not finish successfully.</p></li>
    /// <li>
    /// <p><code>FAILED</code> indicates that the execution failed.</p></li>
    /// <li>
    /// <p><code>STOP_PENDING</code> indicates that the cluster has received a <code>StopNotebookExecution</code> request and the stop is pending.</p></li>
    /// <li>
    /// <p><code>STOPPING</code> indicates that the cluster is in the process of stopping the execution as a result of a <code>StopNotebookExecution</code> request.</p></li>
    /// <li>
    /// <p><code>STOPPED</code> indicates that the execution stopped because of a <code>StopNotebookExecution</code> request.</p></li>
    /// </ul>
    pub fn status(mut self, input: crate::types::NotebookExecutionStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the notebook execution.</p>
    /// <ul>
    /// <li>
    /// <p><code>START_PENDING</code> indicates that the cluster has received the execution request but execution has not begun.</p></li>
    /// <li>
    /// <p><code>STARTING</code> indicates that the execution is starting on the cluster.</p></li>
    /// <li>
    /// <p><code>RUNNING</code> indicates that the execution is being processed by the cluster.</p></li>
    /// <li>
    /// <p><code>FINISHING</code> indicates that execution processing is in the final stages.</p></li>
    /// <li>
    /// <p><code>FINISHED</code> indicates that the execution has completed without error.</p></li>
    /// <li>
    /// <p><code>FAILING</code> indicates that the execution is failing and will not finish successfully.</p></li>
    /// <li>
    /// <p><code>FAILED</code> indicates that the execution failed.</p></li>
    /// <li>
    /// <p><code>STOP_PENDING</code> indicates that the cluster has received a <code>StopNotebookExecution</code> request and the stop is pending.</p></li>
    /// <li>
    /// <p><code>STOPPING</code> indicates that the cluster is in the process of stopping the execution as a result of a <code>StopNotebookExecution</code> request.</p></li>
    /// <li>
    /// <p><code>STOPPED</code> indicates that the execution stopped because of a <code>StopNotebookExecution</code> request.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::NotebookExecutionStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the notebook execution.</p>
    /// <ul>
    /// <li>
    /// <p><code>START_PENDING</code> indicates that the cluster has received the execution request but execution has not begun.</p></li>
    /// <li>
    /// <p><code>STARTING</code> indicates that the execution is starting on the cluster.</p></li>
    /// <li>
    /// <p><code>RUNNING</code> indicates that the execution is being processed by the cluster.</p></li>
    /// <li>
    /// <p><code>FINISHING</code> indicates that execution processing is in the final stages.</p></li>
    /// <li>
    /// <p><code>FINISHED</code> indicates that the execution has completed without error.</p></li>
    /// <li>
    /// <p><code>FAILING</code> indicates that the execution is failing and will not finish successfully.</p></li>
    /// <li>
    /// <p><code>FAILED</code> indicates that the execution failed.</p></li>
    /// <li>
    /// <p><code>STOP_PENDING</code> indicates that the cluster has received a <code>StopNotebookExecution</code> request and the stop is pending.</p></li>
    /// <li>
    /// <p><code>STOPPING</code> indicates that the cluster is in the process of stopping the execution as a result of a <code>StopNotebookExecution</code> request.</p></li>
    /// <li>
    /// <p><code>STOPPED</code> indicates that the execution stopped because of a <code>StopNotebookExecution</code> request.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::NotebookExecutionStatus> {
        &self.status
    }
    /// <p>The timestamp when notebook execution started.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when notebook execution started.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The timestamp when notebook execution started.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The timestamp when notebook execution started.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when notebook execution started.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The timestamp when notebook execution started.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// <p>The Amazon S3 location that stores the notebook execution input.</p>
    pub fn notebook_s3_location(mut self, input: crate::types::NotebookS3LocationForOutput) -> Self {
        self.notebook_s3_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon S3 location that stores the notebook execution input.</p>
    pub fn set_notebook_s3_location(mut self, input: ::std::option::Option<crate::types::NotebookS3LocationForOutput>) -> Self {
        self.notebook_s3_location = input;
        self
    }
    /// <p>The Amazon S3 location that stores the notebook execution input.</p>
    pub fn get_notebook_s3_location(&self) -> &::std::option::Option<crate::types::NotebookS3LocationForOutput> {
        &self.notebook_s3_location
    }
    /// <p>The unique ID of the execution engine for the notebook execution.</p>
    pub fn execution_engine_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_engine_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of the execution engine for the notebook execution.</p>
    pub fn set_execution_engine_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_engine_id = input;
        self
    }
    /// <p>The unique ID of the execution engine for the notebook execution.</p>
    pub fn get_execution_engine_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_engine_id
    }
    /// Consumes the builder and constructs a [`NotebookExecutionSummary`](crate::types::NotebookExecutionSummary).
    pub fn build(self) -> crate::types::NotebookExecutionSummary {
        crate::types::NotebookExecutionSummary {
            notebook_execution_id: self.notebook_execution_id,
            editor_id: self.editor_id,
            notebook_execution_name: self.notebook_execution_name,
            status: self.status,
            start_time: self.start_time,
            end_time: self.end_time,
            notebook_s3_location: self.notebook_s3_location,
            execution_engine_id: self.execution_engine_id,
        }
    }
}
