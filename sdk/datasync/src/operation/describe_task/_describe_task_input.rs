// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>DescribeTaskRequest</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeTaskInput {
    /// <p>Specifies the Amazon Resource Name (ARN) of the transfer task that you want information about.</p>
    pub task_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeTaskInput {
    /// <p>Specifies the Amazon Resource Name (ARN) of the transfer task that you want information about.</p>
    pub fn task_arn(&self) -> ::std::option::Option<&str> {
        self.task_arn.as_deref()
    }
}
impl DescribeTaskInput {
    /// Creates a new builder-style object to manufacture [`DescribeTaskInput`](crate::operation::describe_task::DescribeTaskInput).
    pub fn builder() -> crate::operation::describe_task::builders::DescribeTaskInputBuilder {
        crate::operation::describe_task::builders::DescribeTaskInputBuilder::default()
    }
}

/// A builder for [`DescribeTaskInput`](crate::operation::describe_task::DescribeTaskInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeTaskInputBuilder {
    pub(crate) task_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeTaskInputBuilder {
    /// <p>Specifies the Amazon Resource Name (ARN) of the transfer task that you want information about.</p>
    /// This field is required.
    pub fn task_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the Amazon Resource Name (ARN) of the transfer task that you want information about.</p>
    pub fn set_task_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_arn = input;
        self
    }
    /// <p>Specifies the Amazon Resource Name (ARN) of the transfer task that you want information about.</p>
    pub fn get_task_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_arn
    }
    /// Consumes the builder and constructs a [`DescribeTaskInput`](crate::operation::describe_task::DescribeTaskInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_task::DescribeTaskInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_task::DescribeTaskInput { task_arn: self.task_arn })
    }
}
