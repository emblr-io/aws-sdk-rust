// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Settings related to idle shutdown of Studio applications in a space.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SpaceIdleSettings {
    /// <p>The time that SageMaker waits after the application becomes idle before shutting it down.</p>
    pub idle_timeout_in_minutes: ::std::option::Option<i32>,
}
impl SpaceIdleSettings {
    /// <p>The time that SageMaker waits after the application becomes idle before shutting it down.</p>
    pub fn idle_timeout_in_minutes(&self) -> ::std::option::Option<i32> {
        self.idle_timeout_in_minutes
    }
}
impl SpaceIdleSettings {
    /// Creates a new builder-style object to manufacture [`SpaceIdleSettings`](crate::types::SpaceIdleSettings).
    pub fn builder() -> crate::types::builders::SpaceIdleSettingsBuilder {
        crate::types::builders::SpaceIdleSettingsBuilder::default()
    }
}

/// A builder for [`SpaceIdleSettings`](crate::types::SpaceIdleSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SpaceIdleSettingsBuilder {
    pub(crate) idle_timeout_in_minutes: ::std::option::Option<i32>,
}
impl SpaceIdleSettingsBuilder {
    /// <p>The time that SageMaker waits after the application becomes idle before shutting it down.</p>
    pub fn idle_timeout_in_minutes(mut self, input: i32) -> Self {
        self.idle_timeout_in_minutes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that SageMaker waits after the application becomes idle before shutting it down.</p>
    pub fn set_idle_timeout_in_minutes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.idle_timeout_in_minutes = input;
        self
    }
    /// <p>The time that SageMaker waits after the application becomes idle before shutting it down.</p>
    pub fn get_idle_timeout_in_minutes(&self) -> &::std::option::Option<i32> {
        &self.idle_timeout_in_minutes
    }
    /// Consumes the builder and constructs a [`SpaceIdleSettings`](crate::types::SpaceIdleSettings).
    pub fn build(self) -> crate::types::SpaceIdleSettings {
        crate::types::SpaceIdleSettings {
            idle_timeout_in_minutes: self.idle_timeout_in_minutes,
        }
    }
}
