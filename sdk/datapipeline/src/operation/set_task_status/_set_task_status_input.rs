// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the parameters for SetTaskStatus.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SetTaskStatusInput {
    /// <p>The ID of the task assigned to the task runner. This value is provided in the response for <code>PollForTask</code>.</p>
    pub task_id: ::std::option::Option<::std::string::String>,
    /// <p>If <code>FINISHED</code>, the task successfully completed. If <code>FAILED</code>, the task ended unsuccessfully. Preconditions use false.</p>
    pub task_status: ::std::option::Option<crate::types::TaskStatus>,
    /// <p>If an error occurred during the task, this value specifies the error code. This value is set on the physical attempt object. It is used to display error information to the user. It should not start with string "Service_" which is reserved by the system.</p>
    pub error_id: ::std::option::Option<::std::string::String>,
    /// <p>If an error occurred during the task, this value specifies a text description of the error. This value is set on the physical attempt object. It is used to display error information to the user. The web service does not parse this value.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
    /// <p>If an error occurred during the task, this value specifies the stack trace associated with the error. This value is set on the physical attempt object. It is used to display error information to the user. The web service does not parse this value.</p>
    pub error_stack_trace: ::std::option::Option<::std::string::String>,
}
impl SetTaskStatusInput {
    /// <p>The ID of the task assigned to the task runner. This value is provided in the response for <code>PollForTask</code>.</p>
    pub fn task_id(&self) -> ::std::option::Option<&str> {
        self.task_id.as_deref()
    }
    /// <p>If <code>FINISHED</code>, the task successfully completed. If <code>FAILED</code>, the task ended unsuccessfully. Preconditions use false.</p>
    pub fn task_status(&self) -> ::std::option::Option<&crate::types::TaskStatus> {
        self.task_status.as_ref()
    }
    /// <p>If an error occurred during the task, this value specifies the error code. This value is set on the physical attempt object. It is used to display error information to the user. It should not start with string "Service_" which is reserved by the system.</p>
    pub fn error_id(&self) -> ::std::option::Option<&str> {
        self.error_id.as_deref()
    }
    /// <p>If an error occurred during the task, this value specifies a text description of the error. This value is set on the physical attempt object. It is used to display error information to the user. The web service does not parse this value.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
    /// <p>If an error occurred during the task, this value specifies the stack trace associated with the error. This value is set on the physical attempt object. It is used to display error information to the user. The web service does not parse this value.</p>
    pub fn error_stack_trace(&self) -> ::std::option::Option<&str> {
        self.error_stack_trace.as_deref()
    }
}
impl SetTaskStatusInput {
    /// Creates a new builder-style object to manufacture [`SetTaskStatusInput`](crate::operation::set_task_status::SetTaskStatusInput).
    pub fn builder() -> crate::operation::set_task_status::builders::SetTaskStatusInputBuilder {
        crate::operation::set_task_status::builders::SetTaskStatusInputBuilder::default()
    }
}

/// A builder for [`SetTaskStatusInput`](crate::operation::set_task_status::SetTaskStatusInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SetTaskStatusInputBuilder {
    pub(crate) task_id: ::std::option::Option<::std::string::String>,
    pub(crate) task_status: ::std::option::Option<crate::types::TaskStatus>,
    pub(crate) error_id: ::std::option::Option<::std::string::String>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
    pub(crate) error_stack_trace: ::std::option::Option<::std::string::String>,
}
impl SetTaskStatusInputBuilder {
    /// <p>The ID of the task assigned to the task runner. This value is provided in the response for <code>PollForTask</code>.</p>
    /// This field is required.
    pub fn task_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the task assigned to the task runner. This value is provided in the response for <code>PollForTask</code>.</p>
    pub fn set_task_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_id = input;
        self
    }
    /// <p>The ID of the task assigned to the task runner. This value is provided in the response for <code>PollForTask</code>.</p>
    pub fn get_task_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_id
    }
    /// <p>If <code>FINISHED</code>, the task successfully completed. If <code>FAILED</code>, the task ended unsuccessfully. Preconditions use false.</p>
    /// This field is required.
    pub fn task_status(mut self, input: crate::types::TaskStatus) -> Self {
        self.task_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>If <code>FINISHED</code>, the task successfully completed. If <code>FAILED</code>, the task ended unsuccessfully. Preconditions use false.</p>
    pub fn set_task_status(mut self, input: ::std::option::Option<crate::types::TaskStatus>) -> Self {
        self.task_status = input;
        self
    }
    /// <p>If <code>FINISHED</code>, the task successfully completed. If <code>FAILED</code>, the task ended unsuccessfully. Preconditions use false.</p>
    pub fn get_task_status(&self) -> &::std::option::Option<crate::types::TaskStatus> {
        &self.task_status
    }
    /// <p>If an error occurred during the task, this value specifies the error code. This value is set on the physical attempt object. It is used to display error information to the user. It should not start with string "Service_" which is reserved by the system.</p>
    pub fn error_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If an error occurred during the task, this value specifies the error code. This value is set on the physical attempt object. It is used to display error information to the user. It should not start with string "Service_" which is reserved by the system.</p>
    pub fn set_error_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_id = input;
        self
    }
    /// <p>If an error occurred during the task, this value specifies the error code. This value is set on the physical attempt object. It is used to display error information to the user. It should not start with string "Service_" which is reserved by the system.</p>
    pub fn get_error_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_id
    }
    /// <p>If an error occurred during the task, this value specifies a text description of the error. This value is set on the physical attempt object. It is used to display error information to the user. The web service does not parse this value.</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If an error occurred during the task, this value specifies a text description of the error. This value is set on the physical attempt object. It is used to display error information to the user. The web service does not parse this value.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>If an error occurred during the task, this value specifies a text description of the error. This value is set on the physical attempt object. It is used to display error information to the user. The web service does not parse this value.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// <p>If an error occurred during the task, this value specifies the stack trace associated with the error. This value is set on the physical attempt object. It is used to display error information to the user. The web service does not parse this value.</p>
    pub fn error_stack_trace(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_stack_trace = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If an error occurred during the task, this value specifies the stack trace associated with the error. This value is set on the physical attempt object. It is used to display error information to the user. The web service does not parse this value.</p>
    pub fn set_error_stack_trace(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_stack_trace = input;
        self
    }
    /// <p>If an error occurred during the task, this value specifies the stack trace associated with the error. This value is set on the physical attempt object. It is used to display error information to the user. The web service does not parse this value.</p>
    pub fn get_error_stack_trace(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_stack_trace
    }
    /// Consumes the builder and constructs a [`SetTaskStatusInput`](crate::operation::set_task_status::SetTaskStatusInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::set_task_status::SetTaskStatusInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::set_task_status::SetTaskStatusInput {
            task_id: self.task_id,
            task_status: self.task_status,
            error_id: self.error_id,
            error_message: self.error_message,
            error_stack_trace: self.error_stack_trace,
        })
    }
}
