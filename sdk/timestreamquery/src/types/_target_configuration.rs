// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration used for writing the output of a query.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TargetConfiguration {
    /// <p>Configuration needed to write data into the Timestream database and table.</p>
    pub timestream_configuration: ::std::option::Option<crate::types::TimestreamConfiguration>,
}
impl TargetConfiguration {
    /// <p>Configuration needed to write data into the Timestream database and table.</p>
    pub fn timestream_configuration(&self) -> ::std::option::Option<&crate::types::TimestreamConfiguration> {
        self.timestream_configuration.as_ref()
    }
}
impl TargetConfiguration {
    /// Creates a new builder-style object to manufacture [`TargetConfiguration`](crate::types::TargetConfiguration).
    pub fn builder() -> crate::types::builders::TargetConfigurationBuilder {
        crate::types::builders::TargetConfigurationBuilder::default()
    }
}

/// A builder for [`TargetConfiguration`](crate::types::TargetConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TargetConfigurationBuilder {
    pub(crate) timestream_configuration: ::std::option::Option<crate::types::TimestreamConfiguration>,
}
impl TargetConfigurationBuilder {
    /// <p>Configuration needed to write data into the Timestream database and table.</p>
    /// This field is required.
    pub fn timestream_configuration(mut self, input: crate::types::TimestreamConfiguration) -> Self {
        self.timestream_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration needed to write data into the Timestream database and table.</p>
    pub fn set_timestream_configuration(mut self, input: ::std::option::Option<crate::types::TimestreamConfiguration>) -> Self {
        self.timestream_configuration = input;
        self
    }
    /// <p>Configuration needed to write data into the Timestream database and table.</p>
    pub fn get_timestream_configuration(&self) -> &::std::option::Option<crate::types::TimestreamConfiguration> {
        &self.timestream_configuration
    }
    /// Consumes the builder and constructs a [`TargetConfiguration`](crate::types::TargetConfiguration).
    pub fn build(self) -> crate::types::TargetConfiguration {
        crate::types::TargetConfiguration {
            timestream_configuration: self.timestream_configuration,
        }
    }
}
