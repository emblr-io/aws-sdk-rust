// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The criteria that are used to filter the task runs for the machine learning transform.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TaskRunFilterCriteria {
    /// <p>The type of task run.</p>
    pub task_run_type: ::std::option::Option<crate::types::TaskType>,
    /// <p>The current status of the task run.</p>
    pub status: ::std::option::Option<crate::types::TaskStatusType>,
    /// <p>Filter on task runs started before this date.</p>
    pub started_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Filter on task runs started after this date.</p>
    pub started_after: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl TaskRunFilterCriteria {
    /// <p>The type of task run.</p>
    pub fn task_run_type(&self) -> ::std::option::Option<&crate::types::TaskType> {
        self.task_run_type.as_ref()
    }
    /// <p>The current status of the task run.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::TaskStatusType> {
        self.status.as_ref()
    }
    /// <p>Filter on task runs started before this date.</p>
    pub fn started_before(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.started_before.as_ref()
    }
    /// <p>Filter on task runs started after this date.</p>
    pub fn started_after(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.started_after.as_ref()
    }
}
impl TaskRunFilterCriteria {
    /// Creates a new builder-style object to manufacture [`TaskRunFilterCriteria`](crate::types::TaskRunFilterCriteria).
    pub fn builder() -> crate::types::builders::TaskRunFilterCriteriaBuilder {
        crate::types::builders::TaskRunFilterCriteriaBuilder::default()
    }
}

/// A builder for [`TaskRunFilterCriteria`](crate::types::TaskRunFilterCriteria).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TaskRunFilterCriteriaBuilder {
    pub(crate) task_run_type: ::std::option::Option<crate::types::TaskType>,
    pub(crate) status: ::std::option::Option<crate::types::TaskStatusType>,
    pub(crate) started_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) started_after: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl TaskRunFilterCriteriaBuilder {
    /// <p>The type of task run.</p>
    pub fn task_run_type(mut self, input: crate::types::TaskType) -> Self {
        self.task_run_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of task run.</p>
    pub fn set_task_run_type(mut self, input: ::std::option::Option<crate::types::TaskType>) -> Self {
        self.task_run_type = input;
        self
    }
    /// <p>The type of task run.</p>
    pub fn get_task_run_type(&self) -> &::std::option::Option<crate::types::TaskType> {
        &self.task_run_type
    }
    /// <p>The current status of the task run.</p>
    pub fn status(mut self, input: crate::types::TaskStatusType) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the task run.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::TaskStatusType>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current status of the task run.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::TaskStatusType> {
        &self.status
    }
    /// <p>Filter on task runs started before this date.</p>
    pub fn started_before(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.started_before = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filter on task runs started before this date.</p>
    pub fn set_started_before(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.started_before = input;
        self
    }
    /// <p>Filter on task runs started before this date.</p>
    pub fn get_started_before(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.started_before
    }
    /// <p>Filter on task runs started after this date.</p>
    pub fn started_after(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.started_after = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filter on task runs started after this date.</p>
    pub fn set_started_after(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.started_after = input;
        self
    }
    /// <p>Filter on task runs started after this date.</p>
    pub fn get_started_after(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.started_after
    }
    /// Consumes the builder and constructs a [`TaskRunFilterCriteria`](crate::types::TaskRunFilterCriteria).
    pub fn build(self) -> crate::types::TaskRunFilterCriteria {
        crate::types::TaskRunFilterCriteria {
            task_run_type: self.task_run_type,
            status: self.status,
            started_before: self.started_before,
            started_after: self.started_after,
        }
    }
}
