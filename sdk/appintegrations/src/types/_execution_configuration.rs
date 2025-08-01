// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration for how the files should be pulled from the source.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExecutionConfiguration {
    /// <p>The mode for data import/export execution.</p>
    pub execution_mode: crate::types::ExecutionMode,
    /// <p>The start and end time for data pull from the source.</p>
    pub on_demand_configuration: ::std::option::Option<crate::types::OnDemandConfiguration>,
    /// <p>The name of the data and how often it should be pulled from the source.</p>
    pub schedule_configuration: ::std::option::Option<crate::types::ScheduleConfiguration>,
}
impl ExecutionConfiguration {
    /// <p>The mode for data import/export execution.</p>
    pub fn execution_mode(&self) -> &crate::types::ExecutionMode {
        &self.execution_mode
    }
    /// <p>The start and end time for data pull from the source.</p>
    pub fn on_demand_configuration(&self) -> ::std::option::Option<&crate::types::OnDemandConfiguration> {
        self.on_demand_configuration.as_ref()
    }
    /// <p>The name of the data and how often it should be pulled from the source.</p>
    pub fn schedule_configuration(&self) -> ::std::option::Option<&crate::types::ScheduleConfiguration> {
        self.schedule_configuration.as_ref()
    }
}
impl ExecutionConfiguration {
    /// Creates a new builder-style object to manufacture [`ExecutionConfiguration`](crate::types::ExecutionConfiguration).
    pub fn builder() -> crate::types::builders::ExecutionConfigurationBuilder {
        crate::types::builders::ExecutionConfigurationBuilder::default()
    }
}

/// A builder for [`ExecutionConfiguration`](crate::types::ExecutionConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExecutionConfigurationBuilder {
    pub(crate) execution_mode: ::std::option::Option<crate::types::ExecutionMode>,
    pub(crate) on_demand_configuration: ::std::option::Option<crate::types::OnDemandConfiguration>,
    pub(crate) schedule_configuration: ::std::option::Option<crate::types::ScheduleConfiguration>,
}
impl ExecutionConfigurationBuilder {
    /// <p>The mode for data import/export execution.</p>
    /// This field is required.
    pub fn execution_mode(mut self, input: crate::types::ExecutionMode) -> Self {
        self.execution_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>The mode for data import/export execution.</p>
    pub fn set_execution_mode(mut self, input: ::std::option::Option<crate::types::ExecutionMode>) -> Self {
        self.execution_mode = input;
        self
    }
    /// <p>The mode for data import/export execution.</p>
    pub fn get_execution_mode(&self) -> &::std::option::Option<crate::types::ExecutionMode> {
        &self.execution_mode
    }
    /// <p>The start and end time for data pull from the source.</p>
    pub fn on_demand_configuration(mut self, input: crate::types::OnDemandConfiguration) -> Self {
        self.on_demand_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start and end time for data pull from the source.</p>
    pub fn set_on_demand_configuration(mut self, input: ::std::option::Option<crate::types::OnDemandConfiguration>) -> Self {
        self.on_demand_configuration = input;
        self
    }
    /// <p>The start and end time for data pull from the source.</p>
    pub fn get_on_demand_configuration(&self) -> &::std::option::Option<crate::types::OnDemandConfiguration> {
        &self.on_demand_configuration
    }
    /// <p>The name of the data and how often it should be pulled from the source.</p>
    pub fn schedule_configuration(mut self, input: crate::types::ScheduleConfiguration) -> Self {
        self.schedule_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the data and how often it should be pulled from the source.</p>
    pub fn set_schedule_configuration(mut self, input: ::std::option::Option<crate::types::ScheduleConfiguration>) -> Self {
        self.schedule_configuration = input;
        self
    }
    /// <p>The name of the data and how often it should be pulled from the source.</p>
    pub fn get_schedule_configuration(&self) -> &::std::option::Option<crate::types::ScheduleConfiguration> {
        &self.schedule_configuration
    }
    /// Consumes the builder and constructs a [`ExecutionConfiguration`](crate::types::ExecutionConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`execution_mode`](crate::types::builders::ExecutionConfigurationBuilder::execution_mode)
    pub fn build(self) -> ::std::result::Result<crate::types::ExecutionConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ExecutionConfiguration {
            execution_mode: self.execution_mode.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "execution_mode",
                    "execution_mode was not specified but it is required when building ExecutionConfiguration",
                )
            })?,
            on_demand_configuration: self.on_demand_configuration,
            schedule_configuration: self.schedule_configuration,
        })
    }
}
