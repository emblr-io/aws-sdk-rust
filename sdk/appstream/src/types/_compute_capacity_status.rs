// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the capacity status for a fleet.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ComputeCapacityStatus {
    /// <p>The desired number of streaming instances.</p>
    pub desired: ::std::option::Option<i32>,
    /// <p>The total number of simultaneous streaming instances that are running.</p>
    pub running: ::std::option::Option<i32>,
    /// <p>The number of instances in use for streaming.</p>
    pub in_use: ::std::option::Option<i32>,
    /// <p>The number of currently available instances that can be used to stream sessions.</p>
    pub available: ::std::option::Option<i32>,
    /// <p>The total number of sessions slots that are either running or pending. This represents the total number of concurrent streaming sessions your fleet can support in a steady state.</p>
    /// <p>DesiredUserSessionCapacity = ActualUserSessionCapacity + PendingUserSessionCapacity</p>
    /// <p>This only applies to multi-session fleets.</p>
    pub desired_user_sessions: ::std::option::Option<i32>,
    /// <p>The number of idle session slots currently available for user sessions.</p>
    /// <p>AvailableUserSessionCapacity = ActualUserSessionCapacity - ActiveUserSessions</p>
    /// <p>This only applies to multi-session fleets.</p>
    pub available_user_sessions: ::std::option::Option<i32>,
    /// <p>The number of user sessions currently being used for streaming sessions. This only applies to multi-session fleets.</p>
    pub active_user_sessions: ::std::option::Option<i32>,
    /// <p>The total number of session slots that are available for streaming or are currently streaming.</p>
    /// <p>ActualUserSessionCapacity = AvailableUserSessionCapacity + ActiveUserSessions</p>
    /// <p>This only applies to multi-session fleets.</p>
    pub actual_user_sessions: ::std::option::Option<i32>,
}
impl ComputeCapacityStatus {
    /// <p>The desired number of streaming instances.</p>
    pub fn desired(&self) -> ::std::option::Option<i32> {
        self.desired
    }
    /// <p>The total number of simultaneous streaming instances that are running.</p>
    pub fn running(&self) -> ::std::option::Option<i32> {
        self.running
    }
    /// <p>The number of instances in use for streaming.</p>
    pub fn in_use(&self) -> ::std::option::Option<i32> {
        self.in_use
    }
    /// <p>The number of currently available instances that can be used to stream sessions.</p>
    pub fn available(&self) -> ::std::option::Option<i32> {
        self.available
    }
    /// <p>The total number of sessions slots that are either running or pending. This represents the total number of concurrent streaming sessions your fleet can support in a steady state.</p>
    /// <p>DesiredUserSessionCapacity = ActualUserSessionCapacity + PendingUserSessionCapacity</p>
    /// <p>This only applies to multi-session fleets.</p>
    pub fn desired_user_sessions(&self) -> ::std::option::Option<i32> {
        self.desired_user_sessions
    }
    /// <p>The number of idle session slots currently available for user sessions.</p>
    /// <p>AvailableUserSessionCapacity = ActualUserSessionCapacity - ActiveUserSessions</p>
    /// <p>This only applies to multi-session fleets.</p>
    pub fn available_user_sessions(&self) -> ::std::option::Option<i32> {
        self.available_user_sessions
    }
    /// <p>The number of user sessions currently being used for streaming sessions. This only applies to multi-session fleets.</p>
    pub fn active_user_sessions(&self) -> ::std::option::Option<i32> {
        self.active_user_sessions
    }
    /// <p>The total number of session slots that are available for streaming or are currently streaming.</p>
    /// <p>ActualUserSessionCapacity = AvailableUserSessionCapacity + ActiveUserSessions</p>
    /// <p>This only applies to multi-session fleets.</p>
    pub fn actual_user_sessions(&self) -> ::std::option::Option<i32> {
        self.actual_user_sessions
    }
}
impl ComputeCapacityStatus {
    /// Creates a new builder-style object to manufacture [`ComputeCapacityStatus`](crate::types::ComputeCapacityStatus).
    pub fn builder() -> crate::types::builders::ComputeCapacityStatusBuilder {
        crate::types::builders::ComputeCapacityStatusBuilder::default()
    }
}

/// A builder for [`ComputeCapacityStatus`](crate::types::ComputeCapacityStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ComputeCapacityStatusBuilder {
    pub(crate) desired: ::std::option::Option<i32>,
    pub(crate) running: ::std::option::Option<i32>,
    pub(crate) in_use: ::std::option::Option<i32>,
    pub(crate) available: ::std::option::Option<i32>,
    pub(crate) desired_user_sessions: ::std::option::Option<i32>,
    pub(crate) available_user_sessions: ::std::option::Option<i32>,
    pub(crate) active_user_sessions: ::std::option::Option<i32>,
    pub(crate) actual_user_sessions: ::std::option::Option<i32>,
}
impl ComputeCapacityStatusBuilder {
    /// <p>The desired number of streaming instances.</p>
    /// This field is required.
    pub fn desired(mut self, input: i32) -> Self {
        self.desired = ::std::option::Option::Some(input);
        self
    }
    /// <p>The desired number of streaming instances.</p>
    pub fn set_desired(mut self, input: ::std::option::Option<i32>) -> Self {
        self.desired = input;
        self
    }
    /// <p>The desired number of streaming instances.</p>
    pub fn get_desired(&self) -> &::std::option::Option<i32> {
        &self.desired
    }
    /// <p>The total number of simultaneous streaming instances that are running.</p>
    pub fn running(mut self, input: i32) -> Self {
        self.running = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of simultaneous streaming instances that are running.</p>
    pub fn set_running(mut self, input: ::std::option::Option<i32>) -> Self {
        self.running = input;
        self
    }
    /// <p>The total number of simultaneous streaming instances that are running.</p>
    pub fn get_running(&self) -> &::std::option::Option<i32> {
        &self.running
    }
    /// <p>The number of instances in use for streaming.</p>
    pub fn in_use(mut self, input: i32) -> Self {
        self.in_use = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of instances in use for streaming.</p>
    pub fn set_in_use(mut self, input: ::std::option::Option<i32>) -> Self {
        self.in_use = input;
        self
    }
    /// <p>The number of instances in use for streaming.</p>
    pub fn get_in_use(&self) -> &::std::option::Option<i32> {
        &self.in_use
    }
    /// <p>The number of currently available instances that can be used to stream sessions.</p>
    pub fn available(mut self, input: i32) -> Self {
        self.available = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of currently available instances that can be used to stream sessions.</p>
    pub fn set_available(mut self, input: ::std::option::Option<i32>) -> Self {
        self.available = input;
        self
    }
    /// <p>The number of currently available instances that can be used to stream sessions.</p>
    pub fn get_available(&self) -> &::std::option::Option<i32> {
        &self.available
    }
    /// <p>The total number of sessions slots that are either running or pending. This represents the total number of concurrent streaming sessions your fleet can support in a steady state.</p>
    /// <p>DesiredUserSessionCapacity = ActualUserSessionCapacity + PendingUserSessionCapacity</p>
    /// <p>This only applies to multi-session fleets.</p>
    pub fn desired_user_sessions(mut self, input: i32) -> Self {
        self.desired_user_sessions = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of sessions slots that are either running or pending. This represents the total number of concurrent streaming sessions your fleet can support in a steady state.</p>
    /// <p>DesiredUserSessionCapacity = ActualUserSessionCapacity + PendingUserSessionCapacity</p>
    /// <p>This only applies to multi-session fleets.</p>
    pub fn set_desired_user_sessions(mut self, input: ::std::option::Option<i32>) -> Self {
        self.desired_user_sessions = input;
        self
    }
    /// <p>The total number of sessions slots that are either running or pending. This represents the total number of concurrent streaming sessions your fleet can support in a steady state.</p>
    /// <p>DesiredUserSessionCapacity = ActualUserSessionCapacity + PendingUserSessionCapacity</p>
    /// <p>This only applies to multi-session fleets.</p>
    pub fn get_desired_user_sessions(&self) -> &::std::option::Option<i32> {
        &self.desired_user_sessions
    }
    /// <p>The number of idle session slots currently available for user sessions.</p>
    /// <p>AvailableUserSessionCapacity = ActualUserSessionCapacity - ActiveUserSessions</p>
    /// <p>This only applies to multi-session fleets.</p>
    pub fn available_user_sessions(mut self, input: i32) -> Self {
        self.available_user_sessions = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of idle session slots currently available for user sessions.</p>
    /// <p>AvailableUserSessionCapacity = ActualUserSessionCapacity - ActiveUserSessions</p>
    /// <p>This only applies to multi-session fleets.</p>
    pub fn set_available_user_sessions(mut self, input: ::std::option::Option<i32>) -> Self {
        self.available_user_sessions = input;
        self
    }
    /// <p>The number of idle session slots currently available for user sessions.</p>
    /// <p>AvailableUserSessionCapacity = ActualUserSessionCapacity - ActiveUserSessions</p>
    /// <p>This only applies to multi-session fleets.</p>
    pub fn get_available_user_sessions(&self) -> &::std::option::Option<i32> {
        &self.available_user_sessions
    }
    /// <p>The number of user sessions currently being used for streaming sessions. This only applies to multi-session fleets.</p>
    pub fn active_user_sessions(mut self, input: i32) -> Self {
        self.active_user_sessions = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of user sessions currently being used for streaming sessions. This only applies to multi-session fleets.</p>
    pub fn set_active_user_sessions(mut self, input: ::std::option::Option<i32>) -> Self {
        self.active_user_sessions = input;
        self
    }
    /// <p>The number of user sessions currently being used for streaming sessions. This only applies to multi-session fleets.</p>
    pub fn get_active_user_sessions(&self) -> &::std::option::Option<i32> {
        &self.active_user_sessions
    }
    /// <p>The total number of session slots that are available for streaming or are currently streaming.</p>
    /// <p>ActualUserSessionCapacity = AvailableUserSessionCapacity + ActiveUserSessions</p>
    /// <p>This only applies to multi-session fleets.</p>
    pub fn actual_user_sessions(mut self, input: i32) -> Self {
        self.actual_user_sessions = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of session slots that are available for streaming or are currently streaming.</p>
    /// <p>ActualUserSessionCapacity = AvailableUserSessionCapacity + ActiveUserSessions</p>
    /// <p>This only applies to multi-session fleets.</p>
    pub fn set_actual_user_sessions(mut self, input: ::std::option::Option<i32>) -> Self {
        self.actual_user_sessions = input;
        self
    }
    /// <p>The total number of session slots that are available for streaming or are currently streaming.</p>
    /// <p>ActualUserSessionCapacity = AvailableUserSessionCapacity + ActiveUserSessions</p>
    /// <p>This only applies to multi-session fleets.</p>
    pub fn get_actual_user_sessions(&self) -> &::std::option::Option<i32> {
        &self.actual_user_sessions
    }
    /// Consumes the builder and constructs a [`ComputeCapacityStatus`](crate::types::ComputeCapacityStatus).
    pub fn build(self) -> crate::types::ComputeCapacityStatus {
        crate::types::ComputeCapacityStatus {
            desired: self.desired,
            running: self.running,
            in_use: self.in_use,
            available: self.available,
            desired_user_sessions: self.desired_user_sessions,
            available_user_sessions: self.available_user_sessions,
            active_user_sessions: self.active_user_sessions,
            actual_user_sessions: self.actual_user_sessions,
        }
    }
}
