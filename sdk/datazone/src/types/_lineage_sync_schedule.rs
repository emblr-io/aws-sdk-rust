// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The lineage sync schedule.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LineageSyncSchedule {
    /// <p>The lineage sync schedule.</p>
    pub schedule: ::std::option::Option<::std::string::String>,
}
impl LineageSyncSchedule {
    /// <p>The lineage sync schedule.</p>
    pub fn schedule(&self) -> ::std::option::Option<&str> {
        self.schedule.as_deref()
    }
}
impl LineageSyncSchedule {
    /// Creates a new builder-style object to manufacture [`LineageSyncSchedule`](crate::types::LineageSyncSchedule).
    pub fn builder() -> crate::types::builders::LineageSyncScheduleBuilder {
        crate::types::builders::LineageSyncScheduleBuilder::default()
    }
}

/// A builder for [`LineageSyncSchedule`](crate::types::LineageSyncSchedule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LineageSyncScheduleBuilder {
    pub(crate) schedule: ::std::option::Option<::std::string::String>,
}
impl LineageSyncScheduleBuilder {
    /// <p>The lineage sync schedule.</p>
    pub fn schedule(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schedule = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The lineage sync schedule.</p>
    pub fn set_schedule(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schedule = input;
        self
    }
    /// <p>The lineage sync schedule.</p>
    pub fn get_schedule(&self) -> &::std::option::Option<::std::string::String> {
        &self.schedule
    }
    /// Consumes the builder and constructs a [`LineageSyncSchedule`](crate::types::LineageSyncSchedule).
    pub fn build(self) -> crate::types::LineageSyncSchedule {
        crate::types::LineageSyncSchedule { schedule: self.schedule }
    }
}
