// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Displays the next seven maintenance window occurrences and their start times.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ScheduledJobRollout {
    /// <p>Displays the start times of the next seven maintenance window occurrences.</p>
    pub start_time: ::std::option::Option<::std::string::String>,
}
impl ScheduledJobRollout {
    /// <p>Displays the start times of the next seven maintenance window occurrences.</p>
    pub fn start_time(&self) -> ::std::option::Option<&str> {
        self.start_time.as_deref()
    }
}
impl ScheduledJobRollout {
    /// Creates a new builder-style object to manufacture [`ScheduledJobRollout`](crate::types::ScheduledJobRollout).
    pub fn builder() -> crate::types::builders::ScheduledJobRolloutBuilder {
        crate::types::builders::ScheduledJobRolloutBuilder::default()
    }
}

/// A builder for [`ScheduledJobRollout`](crate::types::ScheduledJobRollout).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScheduledJobRolloutBuilder {
    pub(crate) start_time: ::std::option::Option<::std::string::String>,
}
impl ScheduledJobRolloutBuilder {
    /// <p>Displays the start times of the next seven maintenance window occurrences.</p>
    pub fn start_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.start_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Displays the start times of the next seven maintenance window occurrences.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>Displays the start times of the next seven maintenance window occurrences.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.start_time
    }
    /// Consumes the builder and constructs a [`ScheduledJobRollout`](crate::types::ScheduledJobRollout).
    pub fn build(self) -> crate::types::ScheduledJobRollout {
        crate::types::ScheduledJobRollout { start_time: self.start_time }
    }
}
