// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the configuration details that control the trigger for a flow. Currently, these settings only apply to the Scheduled trigger type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TriggerProperties {
    /// <p>Specifies the configuration details of a schedule-triggered flow that you define.</p>
    pub scheduled: ::std::option::Option<crate::types::ScheduledTriggerProperties>,
}
impl TriggerProperties {
    /// <p>Specifies the configuration details of a schedule-triggered flow that you define.</p>
    pub fn scheduled(&self) -> ::std::option::Option<&crate::types::ScheduledTriggerProperties> {
        self.scheduled.as_ref()
    }
}
impl TriggerProperties {
    /// Creates a new builder-style object to manufacture [`TriggerProperties`](crate::types::TriggerProperties).
    pub fn builder() -> crate::types::builders::TriggerPropertiesBuilder {
        crate::types::builders::TriggerPropertiesBuilder::default()
    }
}

/// A builder for [`TriggerProperties`](crate::types::TriggerProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TriggerPropertiesBuilder {
    pub(crate) scheduled: ::std::option::Option<crate::types::ScheduledTriggerProperties>,
}
impl TriggerPropertiesBuilder {
    /// <p>Specifies the configuration details of a schedule-triggered flow that you define.</p>
    pub fn scheduled(mut self, input: crate::types::ScheduledTriggerProperties) -> Self {
        self.scheduled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the configuration details of a schedule-triggered flow that you define.</p>
    pub fn set_scheduled(mut self, input: ::std::option::Option<crate::types::ScheduledTriggerProperties>) -> Self {
        self.scheduled = input;
        self
    }
    /// <p>Specifies the configuration details of a schedule-triggered flow that you define.</p>
    pub fn get_scheduled(&self) -> &::std::option::Option<crate::types::ScheduledTriggerProperties> {
        &self.scheduled
    }
    /// Consumes the builder and constructs a [`TriggerProperties`](crate::types::TriggerProperties).
    pub fn build(self) -> crate::types::TriggerProperties {
        crate::types::TriggerProperties { scheduled: self.scheduled }
    }
}
