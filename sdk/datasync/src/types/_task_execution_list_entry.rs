// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a single entry in a list of DataSync task executions that's returned with the <a href="https://docs.aws.amazon.com/datasync/latest/userguide/API_ListTaskExecutions.html">ListTaskExecutions</a> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TaskExecutionListEntry {
    /// <p>The Amazon Resource Name (ARN) of a task execution.</p>
    pub task_execution_arn: ::std::option::Option<::std::string::String>,
    /// <p>The status of a task execution. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/understand-task-statuses.html#understand-task-execution-statuses">Task execution statuses</a>.</p>
    pub status: ::std::option::Option<crate::types::TaskExecutionStatus>,
    /// <p>The task mode that you're using. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/choosing-task-mode.html">Choosing a task mode for your data transfer</a>.</p>
    pub task_mode: ::std::option::Option<crate::types::TaskMode>,
}
impl TaskExecutionListEntry {
    /// <p>The Amazon Resource Name (ARN) of a task execution.</p>
    pub fn task_execution_arn(&self) -> ::std::option::Option<&str> {
        self.task_execution_arn.as_deref()
    }
    /// <p>The status of a task execution. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/understand-task-statuses.html#understand-task-execution-statuses">Task execution statuses</a>.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::TaskExecutionStatus> {
        self.status.as_ref()
    }
    /// <p>The task mode that you're using. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/choosing-task-mode.html">Choosing a task mode for your data transfer</a>.</p>
    pub fn task_mode(&self) -> ::std::option::Option<&crate::types::TaskMode> {
        self.task_mode.as_ref()
    }
}
impl TaskExecutionListEntry {
    /// Creates a new builder-style object to manufacture [`TaskExecutionListEntry`](crate::types::TaskExecutionListEntry).
    pub fn builder() -> crate::types::builders::TaskExecutionListEntryBuilder {
        crate::types::builders::TaskExecutionListEntryBuilder::default()
    }
}

/// A builder for [`TaskExecutionListEntry`](crate::types::TaskExecutionListEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TaskExecutionListEntryBuilder {
    pub(crate) task_execution_arn: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::TaskExecutionStatus>,
    pub(crate) task_mode: ::std::option::Option<crate::types::TaskMode>,
}
impl TaskExecutionListEntryBuilder {
    /// <p>The Amazon Resource Name (ARN) of a task execution.</p>
    pub fn task_execution_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_execution_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a task execution.</p>
    pub fn set_task_execution_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_execution_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a task execution.</p>
    pub fn get_task_execution_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_execution_arn
    }
    /// <p>The status of a task execution. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/understand-task-statuses.html#understand-task-execution-statuses">Task execution statuses</a>.</p>
    pub fn status(mut self, input: crate::types::TaskExecutionStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of a task execution. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/understand-task-statuses.html#understand-task-execution-statuses">Task execution statuses</a>.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::TaskExecutionStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of a task execution. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/understand-task-statuses.html#understand-task-execution-statuses">Task execution statuses</a>.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::TaskExecutionStatus> {
        &self.status
    }
    /// <p>The task mode that you're using. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/choosing-task-mode.html">Choosing a task mode for your data transfer</a>.</p>
    pub fn task_mode(mut self, input: crate::types::TaskMode) -> Self {
        self.task_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>The task mode that you're using. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/choosing-task-mode.html">Choosing a task mode for your data transfer</a>.</p>
    pub fn set_task_mode(mut self, input: ::std::option::Option<crate::types::TaskMode>) -> Self {
        self.task_mode = input;
        self
    }
    /// <p>The task mode that you're using. For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/choosing-task-mode.html">Choosing a task mode for your data transfer</a>.</p>
    pub fn get_task_mode(&self) -> &::std::option::Option<crate::types::TaskMode> {
        &self.task_mode
    }
    /// Consumes the builder and constructs a [`TaskExecutionListEntry`](crate::types::TaskExecutionListEntry).
    pub fn build(self) -> crate::types::TaskExecutionListEntry {
        crate::types::TaskExecutionListEntry {
            task_execution_arn: self.task_execution_arn,
            status: self.status,
            task_mode: self.task_mode,
        }
    }
}
