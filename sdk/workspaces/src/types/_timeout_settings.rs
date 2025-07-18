// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the timeout settings for a pool of WorkSpaces.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TimeoutSettings {
    /// <p>Specifies the amount of time, in seconds, that a streaming session remains active after users disconnect. If users try to reconnect to the streaming session after a disconnection or network interruption within the time set, they are connected to their previous session. Otherwise, they are connected to a new session with a new streaming instance.</p>
    pub disconnect_timeout_in_seconds: ::std::option::Option<i32>,
    /// <p>The amount of time in seconds a connection will stay active while idle.</p>
    pub idle_disconnect_timeout_in_seconds: ::std::option::Option<i32>,
    /// <p>Specifies the maximum amount of time, in seconds, that a streaming session can remain active. If users are still connected to a streaming instance five minutes before this limit is reached, they are prompted to save any open documents before being disconnected. After this time elapses, the instance is terminated and replaced by a new instance.</p>
    pub max_user_duration_in_seconds: ::std::option::Option<i32>,
}
impl TimeoutSettings {
    /// <p>Specifies the amount of time, in seconds, that a streaming session remains active after users disconnect. If users try to reconnect to the streaming session after a disconnection or network interruption within the time set, they are connected to their previous session. Otherwise, they are connected to a new session with a new streaming instance.</p>
    pub fn disconnect_timeout_in_seconds(&self) -> ::std::option::Option<i32> {
        self.disconnect_timeout_in_seconds
    }
    /// <p>The amount of time in seconds a connection will stay active while idle.</p>
    pub fn idle_disconnect_timeout_in_seconds(&self) -> ::std::option::Option<i32> {
        self.idle_disconnect_timeout_in_seconds
    }
    /// <p>Specifies the maximum amount of time, in seconds, that a streaming session can remain active. If users are still connected to a streaming instance five minutes before this limit is reached, they are prompted to save any open documents before being disconnected. After this time elapses, the instance is terminated and replaced by a new instance.</p>
    pub fn max_user_duration_in_seconds(&self) -> ::std::option::Option<i32> {
        self.max_user_duration_in_seconds
    }
}
impl TimeoutSettings {
    /// Creates a new builder-style object to manufacture [`TimeoutSettings`](crate::types::TimeoutSettings).
    pub fn builder() -> crate::types::builders::TimeoutSettingsBuilder {
        crate::types::builders::TimeoutSettingsBuilder::default()
    }
}

/// A builder for [`TimeoutSettings`](crate::types::TimeoutSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TimeoutSettingsBuilder {
    pub(crate) disconnect_timeout_in_seconds: ::std::option::Option<i32>,
    pub(crate) idle_disconnect_timeout_in_seconds: ::std::option::Option<i32>,
    pub(crate) max_user_duration_in_seconds: ::std::option::Option<i32>,
}
impl TimeoutSettingsBuilder {
    /// <p>Specifies the amount of time, in seconds, that a streaming session remains active after users disconnect. If users try to reconnect to the streaming session after a disconnection or network interruption within the time set, they are connected to their previous session. Otherwise, they are connected to a new session with a new streaming instance.</p>
    pub fn disconnect_timeout_in_seconds(mut self, input: i32) -> Self {
        self.disconnect_timeout_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the amount of time, in seconds, that a streaming session remains active after users disconnect. If users try to reconnect to the streaming session after a disconnection or network interruption within the time set, they are connected to their previous session. Otherwise, they are connected to a new session with a new streaming instance.</p>
    pub fn set_disconnect_timeout_in_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.disconnect_timeout_in_seconds = input;
        self
    }
    /// <p>Specifies the amount of time, in seconds, that a streaming session remains active after users disconnect. If users try to reconnect to the streaming session after a disconnection or network interruption within the time set, they are connected to their previous session. Otherwise, they are connected to a new session with a new streaming instance.</p>
    pub fn get_disconnect_timeout_in_seconds(&self) -> &::std::option::Option<i32> {
        &self.disconnect_timeout_in_seconds
    }
    /// <p>The amount of time in seconds a connection will stay active while idle.</p>
    pub fn idle_disconnect_timeout_in_seconds(mut self, input: i32) -> Self {
        self.idle_disconnect_timeout_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of time in seconds a connection will stay active while idle.</p>
    pub fn set_idle_disconnect_timeout_in_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.idle_disconnect_timeout_in_seconds = input;
        self
    }
    /// <p>The amount of time in seconds a connection will stay active while idle.</p>
    pub fn get_idle_disconnect_timeout_in_seconds(&self) -> &::std::option::Option<i32> {
        &self.idle_disconnect_timeout_in_seconds
    }
    /// <p>Specifies the maximum amount of time, in seconds, that a streaming session can remain active. If users are still connected to a streaming instance five minutes before this limit is reached, they are prompted to save any open documents before being disconnected. After this time elapses, the instance is terminated and replaced by a new instance.</p>
    pub fn max_user_duration_in_seconds(mut self, input: i32) -> Self {
        self.max_user_duration_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the maximum amount of time, in seconds, that a streaming session can remain active. If users are still connected to a streaming instance five minutes before this limit is reached, they are prompted to save any open documents before being disconnected. After this time elapses, the instance is terminated and replaced by a new instance.</p>
    pub fn set_max_user_duration_in_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_user_duration_in_seconds = input;
        self
    }
    /// <p>Specifies the maximum amount of time, in seconds, that a streaming session can remain active. If users are still connected to a streaming instance five minutes before this limit is reached, they are prompted to save any open documents before being disconnected. After this time elapses, the instance is terminated and replaced by a new instance.</p>
    pub fn get_max_user_duration_in_seconds(&self) -> &::std::option::Option<i32> {
        &self.max_user_duration_in_seconds
    }
    /// Consumes the builder and constructs a [`TimeoutSettings`](crate::types::TimeoutSettings).
    pub fn build(self) -> crate::types::TimeoutSettings {
        crate::types::TimeoutSettings {
            disconnect_timeout_in_seconds: self.disconnect_timeout_in_seconds,
            idle_disconnect_timeout_in_seconds: self.idle_disconnect_timeout_in_seconds,
            max_user_duration_in_seconds: self.max_user_duration_in_seconds,
        }
    }
}
