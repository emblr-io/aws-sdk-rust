// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetScheduleInput {
    /// <p>The name of the schedule to retrieve.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the schedule group associated with this schedule. If you omit this, EventBridge Scheduler assumes that the schedule is associated with the default group.</p>
    pub group_name: ::std::option::Option<::std::string::String>,
}
impl GetScheduleInput {
    /// <p>The name of the schedule to retrieve.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The name of the schedule group associated with this schedule. If you omit this, EventBridge Scheduler assumes that the schedule is associated with the default group.</p>
    pub fn group_name(&self) -> ::std::option::Option<&str> {
        self.group_name.as_deref()
    }
}
impl GetScheduleInput {
    /// Creates a new builder-style object to manufacture [`GetScheduleInput`](crate::operation::get_schedule::GetScheduleInput).
    pub fn builder() -> crate::operation::get_schedule::builders::GetScheduleInputBuilder {
        crate::operation::get_schedule::builders::GetScheduleInputBuilder::default()
    }
}

/// A builder for [`GetScheduleInput`](crate::operation::get_schedule::GetScheduleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetScheduleInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) group_name: ::std::option::Option<::std::string::String>,
}
impl GetScheduleInputBuilder {
    /// <p>The name of the schedule to retrieve.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the schedule to retrieve.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the schedule to retrieve.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The name of the schedule group associated with this schedule. If you omit this, EventBridge Scheduler assumes that the schedule is associated with the default group.</p>
    pub fn group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the schedule group associated with this schedule. If you omit this, EventBridge Scheduler assumes that the schedule is associated with the default group.</p>
    pub fn set_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_name = input;
        self
    }
    /// <p>The name of the schedule group associated with this schedule. If you omit this, EventBridge Scheduler assumes that the schedule is associated with the default group.</p>
    pub fn get_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_name
    }
    /// Consumes the builder and constructs a [`GetScheduleInput`](crate::operation::get_schedule::GetScheduleInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_schedule::GetScheduleInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_schedule::GetScheduleInput {
            name: self.name,
            group_name: self.group_name,
        })
    }
}
