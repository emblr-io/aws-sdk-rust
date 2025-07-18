// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes scaling activity, which is a long-running process that represents a change to your Auto Scaling group, such as changing its size or replacing an instance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Activity {
    /// <p>The ID of the activity.</p>
    pub activity_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the Auto Scaling group.</p>
    pub auto_scaling_group_name: ::std::option::Option<::std::string::String>,
    /// <p>A friendly, more verbose description of the activity.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The reason the activity began.</p>
    pub cause: ::std::option::Option<::std::string::String>,
    /// <p>The start time of the activity.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The end time of the activity.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The current status of the activity.</p>
    pub status_code: ::std::option::Option<crate::types::ScalingActivityStatusCode>,
    /// <p>A friendly, more verbose description of the activity status.</p>
    pub status_message: ::std::option::Option<::std::string::String>,
    /// <p>A value between 0 and 100 that indicates the progress of the activity.</p>
    pub progress: ::std::option::Option<i32>,
    /// <p>The details about the activity.</p>
    pub details: ::std::option::Option<::std::string::String>,
    /// <p>The state of the Auto Scaling group, which is either <code>InService</code> or <code>Deleted</code>.</p>
    pub auto_scaling_group_state: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the Auto Scaling group.</p>
    pub auto_scaling_group_arn: ::std::option::Option<::std::string::String>,
}
impl Activity {
    /// <p>The ID of the activity.</p>
    pub fn activity_id(&self) -> ::std::option::Option<&str> {
        self.activity_id.as_deref()
    }
    /// <p>The name of the Auto Scaling group.</p>
    pub fn auto_scaling_group_name(&self) -> ::std::option::Option<&str> {
        self.auto_scaling_group_name.as_deref()
    }
    /// <p>A friendly, more verbose description of the activity.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The reason the activity began.</p>
    pub fn cause(&self) -> ::std::option::Option<&str> {
        self.cause.as_deref()
    }
    /// <p>The start time of the activity.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The end time of the activity.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
    /// <p>The current status of the activity.</p>
    pub fn status_code(&self) -> ::std::option::Option<&crate::types::ScalingActivityStatusCode> {
        self.status_code.as_ref()
    }
    /// <p>A friendly, more verbose description of the activity status.</p>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
    /// <p>A value between 0 and 100 that indicates the progress of the activity.</p>
    pub fn progress(&self) -> ::std::option::Option<i32> {
        self.progress
    }
    /// <p>The details about the activity.</p>
    pub fn details(&self) -> ::std::option::Option<&str> {
        self.details.as_deref()
    }
    /// <p>The state of the Auto Scaling group, which is either <code>InService</code> or <code>Deleted</code>.</p>
    pub fn auto_scaling_group_state(&self) -> ::std::option::Option<&str> {
        self.auto_scaling_group_state.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the Auto Scaling group.</p>
    pub fn auto_scaling_group_arn(&self) -> ::std::option::Option<&str> {
        self.auto_scaling_group_arn.as_deref()
    }
}
impl Activity {
    /// Creates a new builder-style object to manufacture [`Activity`](crate::types::Activity).
    pub fn builder() -> crate::types::builders::ActivityBuilder {
        crate::types::builders::ActivityBuilder::default()
    }
}

/// A builder for [`Activity`](crate::types::Activity).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ActivityBuilder {
    pub(crate) activity_id: ::std::option::Option<::std::string::String>,
    pub(crate) auto_scaling_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) cause: ::std::option::Option<::std::string::String>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) status_code: ::std::option::Option<crate::types::ScalingActivityStatusCode>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
    pub(crate) progress: ::std::option::Option<i32>,
    pub(crate) details: ::std::option::Option<::std::string::String>,
    pub(crate) auto_scaling_group_state: ::std::option::Option<::std::string::String>,
    pub(crate) auto_scaling_group_arn: ::std::option::Option<::std::string::String>,
}
impl ActivityBuilder {
    /// <p>The ID of the activity.</p>
    /// This field is required.
    pub fn activity_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.activity_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the activity.</p>
    pub fn set_activity_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.activity_id = input;
        self
    }
    /// <p>The ID of the activity.</p>
    pub fn get_activity_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.activity_id
    }
    /// <p>The name of the Auto Scaling group.</p>
    /// This field is required.
    pub fn auto_scaling_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.auto_scaling_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Auto Scaling group.</p>
    pub fn set_auto_scaling_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.auto_scaling_group_name = input;
        self
    }
    /// <p>The name of the Auto Scaling group.</p>
    pub fn get_auto_scaling_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.auto_scaling_group_name
    }
    /// <p>A friendly, more verbose description of the activity.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A friendly, more verbose description of the activity.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A friendly, more verbose description of the activity.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The reason the activity began.</p>
    /// This field is required.
    pub fn cause(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cause = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reason the activity began.</p>
    pub fn set_cause(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cause = input;
        self
    }
    /// <p>The reason the activity began.</p>
    pub fn get_cause(&self) -> &::std::option::Option<::std::string::String> {
        &self.cause
    }
    /// <p>The start time of the activity.</p>
    /// This field is required.
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start time of the activity.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The start time of the activity.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The end time of the activity.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The end time of the activity.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The end time of the activity.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// <p>The current status of the activity.</p>
    /// This field is required.
    pub fn status_code(mut self, input: crate::types::ScalingActivityStatusCode) -> Self {
        self.status_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the activity.</p>
    pub fn set_status_code(mut self, input: ::std::option::Option<crate::types::ScalingActivityStatusCode>) -> Self {
        self.status_code = input;
        self
    }
    /// <p>The current status of the activity.</p>
    pub fn get_status_code(&self) -> &::std::option::Option<crate::types::ScalingActivityStatusCode> {
        &self.status_code
    }
    /// <p>A friendly, more verbose description of the activity status.</p>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A friendly, more verbose description of the activity status.</p>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>A friendly, more verbose description of the activity status.</p>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// <p>A value between 0 and 100 that indicates the progress of the activity.</p>
    pub fn progress(mut self, input: i32) -> Self {
        self.progress = ::std::option::Option::Some(input);
        self
    }
    /// <p>A value between 0 and 100 that indicates the progress of the activity.</p>
    pub fn set_progress(mut self, input: ::std::option::Option<i32>) -> Self {
        self.progress = input;
        self
    }
    /// <p>A value between 0 and 100 that indicates the progress of the activity.</p>
    pub fn get_progress(&self) -> &::std::option::Option<i32> {
        &self.progress
    }
    /// <p>The details about the activity.</p>
    pub fn details(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.details = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The details about the activity.</p>
    pub fn set_details(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.details = input;
        self
    }
    /// <p>The details about the activity.</p>
    pub fn get_details(&self) -> &::std::option::Option<::std::string::String> {
        &self.details
    }
    /// <p>The state of the Auto Scaling group, which is either <code>InService</code> or <code>Deleted</code>.</p>
    pub fn auto_scaling_group_state(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.auto_scaling_group_state = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The state of the Auto Scaling group, which is either <code>InService</code> or <code>Deleted</code>.</p>
    pub fn set_auto_scaling_group_state(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.auto_scaling_group_state = input;
        self
    }
    /// <p>The state of the Auto Scaling group, which is either <code>InService</code> or <code>Deleted</code>.</p>
    pub fn get_auto_scaling_group_state(&self) -> &::std::option::Option<::std::string::String> {
        &self.auto_scaling_group_state
    }
    /// <p>The Amazon Resource Name (ARN) of the Auto Scaling group.</p>
    pub fn auto_scaling_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.auto_scaling_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Auto Scaling group.</p>
    pub fn set_auto_scaling_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.auto_scaling_group_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Auto Scaling group.</p>
    pub fn get_auto_scaling_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.auto_scaling_group_arn
    }
    /// Consumes the builder and constructs a [`Activity`](crate::types::Activity).
    pub fn build(self) -> crate::types::Activity {
        crate::types::Activity {
            activity_id: self.activity_id,
            auto_scaling_group_name: self.auto_scaling_group_name,
            description: self.description,
            cause: self.cause,
            start_time: self.start_time,
            end_time: self.end_time,
            status_code: self.status_code,
            status_message: self.status_message,
            progress: self.progress,
            details: self.details,
            auto_scaling_group_state: self.auto_scaling_group_state,
            auto_scaling_group_arn: self.auto_scaling_group_arn,
        }
    }
}
