// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>CreateTaskResponse</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateTaskOutput {
    /// <p>The Amazon Resource Name (ARN) of the task.</p>
    pub task_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateTaskOutput {
    /// <p>The Amazon Resource Name (ARN) of the task.</p>
    pub fn task_arn(&self) -> ::std::option::Option<&str> {
        self.task_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateTaskOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateTaskOutput {
    /// Creates a new builder-style object to manufacture [`CreateTaskOutput`](crate::operation::create_task::CreateTaskOutput).
    pub fn builder() -> crate::operation::create_task::builders::CreateTaskOutputBuilder {
        crate::operation::create_task::builders::CreateTaskOutputBuilder::default()
    }
}

/// A builder for [`CreateTaskOutput`](crate::operation::create_task::CreateTaskOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateTaskOutputBuilder {
    pub(crate) task_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateTaskOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the task.</p>
    pub fn task_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the task.</p>
    pub fn set_task_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the task.</p>
    pub fn get_task_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateTaskOutput`](crate::operation::create_task::CreateTaskOutput).
    pub fn build(self) -> crate::operation::create_task::CreateTaskOutput {
        crate::operation::create_task::CreateTaskOutput {
            task_arn: self.task_arn,
            _request_id: self._request_id,
        }
    }
}
