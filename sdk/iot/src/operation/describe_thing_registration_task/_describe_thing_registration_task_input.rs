// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeThingRegistrationTaskInput {
    /// <p>The task ID.</p>
    pub task_id: ::std::option::Option<::std::string::String>,
}
impl DescribeThingRegistrationTaskInput {
    /// <p>The task ID.</p>
    pub fn task_id(&self) -> ::std::option::Option<&str> {
        self.task_id.as_deref()
    }
}
impl DescribeThingRegistrationTaskInput {
    /// Creates a new builder-style object to manufacture [`DescribeThingRegistrationTaskInput`](crate::operation::describe_thing_registration_task::DescribeThingRegistrationTaskInput).
    pub fn builder() -> crate::operation::describe_thing_registration_task::builders::DescribeThingRegistrationTaskInputBuilder {
        crate::operation::describe_thing_registration_task::builders::DescribeThingRegistrationTaskInputBuilder::default()
    }
}

/// A builder for [`DescribeThingRegistrationTaskInput`](crate::operation::describe_thing_registration_task::DescribeThingRegistrationTaskInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeThingRegistrationTaskInputBuilder {
    pub(crate) task_id: ::std::option::Option<::std::string::String>,
}
impl DescribeThingRegistrationTaskInputBuilder {
    /// <p>The task ID.</p>
    /// This field is required.
    pub fn task_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The task ID.</p>
    pub fn set_task_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_id = input;
        self
    }
    /// <p>The task ID.</p>
    pub fn get_task_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_id
    }
    /// Consumes the builder and constructs a [`DescribeThingRegistrationTaskInput`](crate::operation::describe_thing_registration_task::DescribeThingRegistrationTaskInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_thing_registration_task::DescribeThingRegistrationTaskInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_thing_registration_task::DescribeThingRegistrationTaskInput { task_id: self.task_id })
    }
}
