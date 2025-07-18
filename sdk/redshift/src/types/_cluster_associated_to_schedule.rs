// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ClusterAssociatedToSchedule {
    /// <p></p>
    pub cluster_identifier: ::std::option::Option<::std::string::String>,
    /// <p></p>
    pub schedule_association_state: ::std::option::Option<crate::types::ScheduleState>,
}
impl ClusterAssociatedToSchedule {
    /// <p></p>
    pub fn cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.cluster_identifier.as_deref()
    }
    /// <p></p>
    pub fn schedule_association_state(&self) -> ::std::option::Option<&crate::types::ScheduleState> {
        self.schedule_association_state.as_ref()
    }
}
impl ClusterAssociatedToSchedule {
    /// Creates a new builder-style object to manufacture [`ClusterAssociatedToSchedule`](crate::types::ClusterAssociatedToSchedule).
    pub fn builder() -> crate::types::builders::ClusterAssociatedToScheduleBuilder {
        crate::types::builders::ClusterAssociatedToScheduleBuilder::default()
    }
}

/// A builder for [`ClusterAssociatedToSchedule`](crate::types::ClusterAssociatedToSchedule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ClusterAssociatedToScheduleBuilder {
    pub(crate) cluster_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) schedule_association_state: ::std::option::Option<crate::types::ScheduleState>,
}
impl ClusterAssociatedToScheduleBuilder {
    /// <p></p>
    pub fn cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p></p>
    pub fn set_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_identifier = input;
        self
    }
    /// <p></p>
    pub fn get_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_identifier
    }
    /// <p></p>
    pub fn schedule_association_state(mut self, input: crate::types::ScheduleState) -> Self {
        self.schedule_association_state = ::std::option::Option::Some(input);
        self
    }
    /// <p></p>
    pub fn set_schedule_association_state(mut self, input: ::std::option::Option<crate::types::ScheduleState>) -> Self {
        self.schedule_association_state = input;
        self
    }
    /// <p></p>
    pub fn get_schedule_association_state(&self) -> &::std::option::Option<crate::types::ScheduleState> {
        &self.schedule_association_state
    }
    /// Consumes the builder and constructs a [`ClusterAssociatedToSchedule`](crate::types::ClusterAssociatedToSchedule).
    pub fn build(self) -> crate::types::ClusterAssociatedToSchedule {
        crate::types::ClusterAssociatedToSchedule {
            cluster_identifier: self.cluster_identifier,
            schedule_association_state: self.schedule_association_state,
        }
    }
}
