// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The record of a completed or failed managed action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ManagedActionHistoryItem {
    /// <p>A unique identifier for the managed action.</p>
    pub action_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of the managed action.</p>
    pub action_type: ::std::option::Option<crate::types::ActionType>,
    /// <p>A description of the managed action.</p>
    pub action_description: ::std::option::Option<::std::string::String>,
    /// <p>If the action failed, the type of failure.</p>
    pub failure_type: ::std::option::Option<crate::types::FailureType>,
    /// <p>The status of the action.</p>
    pub status: ::std::option::Option<crate::types::ActionHistoryStatus>,
    /// <p>If the action failed, a description of the failure.</p>
    pub failure_description: ::std::option::Option<::std::string::String>,
    /// <p>The date and time that the action started executing.</p>
    pub executed_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time that the action finished executing.</p>
    pub finished_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ManagedActionHistoryItem {
    /// <p>A unique identifier for the managed action.</p>
    pub fn action_id(&self) -> ::std::option::Option<&str> {
        self.action_id.as_deref()
    }
    /// <p>The type of the managed action.</p>
    pub fn action_type(&self) -> ::std::option::Option<&crate::types::ActionType> {
        self.action_type.as_ref()
    }
    /// <p>A description of the managed action.</p>
    pub fn action_description(&self) -> ::std::option::Option<&str> {
        self.action_description.as_deref()
    }
    /// <p>If the action failed, the type of failure.</p>
    pub fn failure_type(&self) -> ::std::option::Option<&crate::types::FailureType> {
        self.failure_type.as_ref()
    }
    /// <p>The status of the action.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ActionHistoryStatus> {
        self.status.as_ref()
    }
    /// <p>If the action failed, a description of the failure.</p>
    pub fn failure_description(&self) -> ::std::option::Option<&str> {
        self.failure_description.as_deref()
    }
    /// <p>The date and time that the action started executing.</p>
    pub fn executed_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.executed_time.as_ref()
    }
    /// <p>The date and time that the action finished executing.</p>
    pub fn finished_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.finished_time.as_ref()
    }
}
impl ManagedActionHistoryItem {
    /// Creates a new builder-style object to manufacture [`ManagedActionHistoryItem`](crate::types::ManagedActionHistoryItem).
    pub fn builder() -> crate::types::builders::ManagedActionHistoryItemBuilder {
        crate::types::builders::ManagedActionHistoryItemBuilder::default()
    }
}

/// A builder for [`ManagedActionHistoryItem`](crate::types::ManagedActionHistoryItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ManagedActionHistoryItemBuilder {
    pub(crate) action_id: ::std::option::Option<::std::string::String>,
    pub(crate) action_type: ::std::option::Option<crate::types::ActionType>,
    pub(crate) action_description: ::std::option::Option<::std::string::String>,
    pub(crate) failure_type: ::std::option::Option<crate::types::FailureType>,
    pub(crate) status: ::std::option::Option<crate::types::ActionHistoryStatus>,
    pub(crate) failure_description: ::std::option::Option<::std::string::String>,
    pub(crate) executed_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) finished_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ManagedActionHistoryItemBuilder {
    /// <p>A unique identifier for the managed action.</p>
    pub fn action_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.action_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the managed action.</p>
    pub fn set_action_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.action_id = input;
        self
    }
    /// <p>A unique identifier for the managed action.</p>
    pub fn get_action_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.action_id
    }
    /// <p>The type of the managed action.</p>
    pub fn action_type(mut self, input: crate::types::ActionType) -> Self {
        self.action_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the managed action.</p>
    pub fn set_action_type(mut self, input: ::std::option::Option<crate::types::ActionType>) -> Self {
        self.action_type = input;
        self
    }
    /// <p>The type of the managed action.</p>
    pub fn get_action_type(&self) -> &::std::option::Option<crate::types::ActionType> {
        &self.action_type
    }
    /// <p>A description of the managed action.</p>
    pub fn action_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.action_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the managed action.</p>
    pub fn set_action_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.action_description = input;
        self
    }
    /// <p>A description of the managed action.</p>
    pub fn get_action_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.action_description
    }
    /// <p>If the action failed, the type of failure.</p>
    pub fn failure_type(mut self, input: crate::types::FailureType) -> Self {
        self.failure_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the action failed, the type of failure.</p>
    pub fn set_failure_type(mut self, input: ::std::option::Option<crate::types::FailureType>) -> Self {
        self.failure_type = input;
        self
    }
    /// <p>If the action failed, the type of failure.</p>
    pub fn get_failure_type(&self) -> &::std::option::Option<crate::types::FailureType> {
        &self.failure_type
    }
    /// <p>The status of the action.</p>
    pub fn status(mut self, input: crate::types::ActionHistoryStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the action.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ActionHistoryStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the action.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ActionHistoryStatus> {
        &self.status
    }
    /// <p>If the action failed, a description of the failure.</p>
    pub fn failure_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.failure_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the action failed, a description of the failure.</p>
    pub fn set_failure_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.failure_description = input;
        self
    }
    /// <p>If the action failed, a description of the failure.</p>
    pub fn get_failure_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.failure_description
    }
    /// <p>The date and time that the action started executing.</p>
    pub fn executed_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.executed_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the action started executing.</p>
    pub fn set_executed_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.executed_time = input;
        self
    }
    /// <p>The date and time that the action started executing.</p>
    pub fn get_executed_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.executed_time
    }
    /// <p>The date and time that the action finished executing.</p>
    pub fn finished_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.finished_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the action finished executing.</p>
    pub fn set_finished_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.finished_time = input;
        self
    }
    /// <p>The date and time that the action finished executing.</p>
    pub fn get_finished_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.finished_time
    }
    /// Consumes the builder and constructs a [`ManagedActionHistoryItem`](crate::types::ManagedActionHistoryItem).
    pub fn build(self) -> crate::types::ManagedActionHistoryItem {
        crate::types::ManagedActionHistoryItem {
            action_id: self.action_id,
            action_type: self.action_type,
            action_description: self.action_description,
            failure_type: self.failure_type,
            status: self.status,
            failure_description: self.failure_description,
            executed_time: self.executed_time,
            finished_time: self.finished_time,
        }
    }
}
