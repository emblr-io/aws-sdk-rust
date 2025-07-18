// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The schedules configuration for an embedded Amazon QuickSight dashboard.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SchedulesConfigurations {
    /// <p>The schedules configuration for an embedded Amazon QuickSight dashboard.</p>
    pub enabled: bool,
}
impl SchedulesConfigurations {
    /// <p>The schedules configuration for an embedded Amazon QuickSight dashboard.</p>
    pub fn enabled(&self) -> bool {
        self.enabled
    }
}
impl SchedulesConfigurations {
    /// Creates a new builder-style object to manufacture [`SchedulesConfigurations`](crate::types::SchedulesConfigurations).
    pub fn builder() -> crate::types::builders::SchedulesConfigurationsBuilder {
        crate::types::builders::SchedulesConfigurationsBuilder::default()
    }
}

/// A builder for [`SchedulesConfigurations`](crate::types::SchedulesConfigurations).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SchedulesConfigurationsBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
}
impl SchedulesConfigurationsBuilder {
    /// <p>The schedules configuration for an embedded Amazon QuickSight dashboard.</p>
    /// This field is required.
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>The schedules configuration for an embedded Amazon QuickSight dashboard.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>The schedules configuration for an embedded Amazon QuickSight dashboard.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// Consumes the builder and constructs a [`SchedulesConfigurations`](crate::types::SchedulesConfigurations).
    pub fn build(self) -> crate::types::SchedulesConfigurations {
        crate::types::SchedulesConfigurations {
            enabled: self.enabled.unwrap_or_default(),
        }
    }
}
