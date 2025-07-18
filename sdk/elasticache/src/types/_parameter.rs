// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes an individual setting that controls some aspect of ElastiCache behavior.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Parameter {
    /// <p>The name of the parameter.</p>
    pub parameter_name: ::std::option::Option<::std::string::String>,
    /// <p>The value of the parameter.</p>
    pub parameter_value: ::std::option::Option<::std::string::String>,
    /// <p>A description of the parameter.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The source of the parameter.</p>
    pub source: ::std::option::Option<::std::string::String>,
    /// <p>The valid data type for the parameter.</p>
    pub data_type: ::std::option::Option<::std::string::String>,
    /// <p>The valid range of values for the parameter.</p>
    pub allowed_values: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether (<code>true</code>) or not (<code>false</code>) the parameter can be modified. Some parameters have security or operational implications that prevent them from being changed.</p>
    pub is_modifiable: ::std::option::Option<bool>,
    /// <p>The earliest cache engine version to which the parameter can apply.</p>
    pub minimum_engine_version: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether a change to the parameter is applied immediately or requires a reboot for the change to be applied. You can force a reboot or wait until the next maintenance window's reboot. For more information, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/Clusters.Rebooting.html">Rebooting a Cluster</a>.</p>
    pub change_type: ::std::option::Option<crate::types::ChangeType>,
}
impl Parameter {
    /// <p>The name of the parameter.</p>
    pub fn parameter_name(&self) -> ::std::option::Option<&str> {
        self.parameter_name.as_deref()
    }
    /// <p>The value of the parameter.</p>
    pub fn parameter_value(&self) -> ::std::option::Option<&str> {
        self.parameter_value.as_deref()
    }
    /// <p>A description of the parameter.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The source of the parameter.</p>
    pub fn source(&self) -> ::std::option::Option<&str> {
        self.source.as_deref()
    }
    /// <p>The valid data type for the parameter.</p>
    pub fn data_type(&self) -> ::std::option::Option<&str> {
        self.data_type.as_deref()
    }
    /// <p>The valid range of values for the parameter.</p>
    pub fn allowed_values(&self) -> ::std::option::Option<&str> {
        self.allowed_values.as_deref()
    }
    /// <p>Indicates whether (<code>true</code>) or not (<code>false</code>) the parameter can be modified. Some parameters have security or operational implications that prevent them from being changed.</p>
    pub fn is_modifiable(&self) -> ::std::option::Option<bool> {
        self.is_modifiable
    }
    /// <p>The earliest cache engine version to which the parameter can apply.</p>
    pub fn minimum_engine_version(&self) -> ::std::option::Option<&str> {
        self.minimum_engine_version.as_deref()
    }
    /// <p>Indicates whether a change to the parameter is applied immediately or requires a reboot for the change to be applied. You can force a reboot or wait until the next maintenance window's reboot. For more information, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/Clusters.Rebooting.html">Rebooting a Cluster</a>.</p>
    pub fn change_type(&self) -> ::std::option::Option<&crate::types::ChangeType> {
        self.change_type.as_ref()
    }
}
impl Parameter {
    /// Creates a new builder-style object to manufacture [`Parameter`](crate::types::Parameter).
    pub fn builder() -> crate::types::builders::ParameterBuilder {
        crate::types::builders::ParameterBuilder::default()
    }
}

/// A builder for [`Parameter`](crate::types::Parameter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ParameterBuilder {
    pub(crate) parameter_name: ::std::option::Option<::std::string::String>,
    pub(crate) parameter_value: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) source: ::std::option::Option<::std::string::String>,
    pub(crate) data_type: ::std::option::Option<::std::string::String>,
    pub(crate) allowed_values: ::std::option::Option<::std::string::String>,
    pub(crate) is_modifiable: ::std::option::Option<bool>,
    pub(crate) minimum_engine_version: ::std::option::Option<::std::string::String>,
    pub(crate) change_type: ::std::option::Option<crate::types::ChangeType>,
}
impl ParameterBuilder {
    /// <p>The name of the parameter.</p>
    pub fn parameter_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parameter_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the parameter.</p>
    pub fn set_parameter_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parameter_name = input;
        self
    }
    /// <p>The name of the parameter.</p>
    pub fn get_parameter_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.parameter_name
    }
    /// <p>The value of the parameter.</p>
    pub fn parameter_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parameter_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the parameter.</p>
    pub fn set_parameter_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parameter_value = input;
        self
    }
    /// <p>The value of the parameter.</p>
    pub fn get_parameter_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.parameter_value
    }
    /// <p>A description of the parameter.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the parameter.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the parameter.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The source of the parameter.</p>
    pub fn source(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The source of the parameter.</p>
    pub fn set_source(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source = input;
        self
    }
    /// <p>The source of the parameter.</p>
    pub fn get_source(&self) -> &::std::option::Option<::std::string::String> {
        &self.source
    }
    /// <p>The valid data type for the parameter.</p>
    pub fn data_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The valid data type for the parameter.</p>
    pub fn set_data_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_type = input;
        self
    }
    /// <p>The valid data type for the parameter.</p>
    pub fn get_data_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_type
    }
    /// <p>The valid range of values for the parameter.</p>
    pub fn allowed_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.allowed_values = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The valid range of values for the parameter.</p>
    pub fn set_allowed_values(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.allowed_values = input;
        self
    }
    /// <p>The valid range of values for the parameter.</p>
    pub fn get_allowed_values(&self) -> &::std::option::Option<::std::string::String> {
        &self.allowed_values
    }
    /// <p>Indicates whether (<code>true</code>) or not (<code>false</code>) the parameter can be modified. Some parameters have security or operational implications that prevent them from being changed.</p>
    pub fn is_modifiable(mut self, input: bool) -> Self {
        self.is_modifiable = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether (<code>true</code>) or not (<code>false</code>) the parameter can be modified. Some parameters have security or operational implications that prevent them from being changed.</p>
    pub fn set_is_modifiable(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_modifiable = input;
        self
    }
    /// <p>Indicates whether (<code>true</code>) or not (<code>false</code>) the parameter can be modified. Some parameters have security or operational implications that prevent them from being changed.</p>
    pub fn get_is_modifiable(&self) -> &::std::option::Option<bool> {
        &self.is_modifiable
    }
    /// <p>The earliest cache engine version to which the parameter can apply.</p>
    pub fn minimum_engine_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.minimum_engine_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The earliest cache engine version to which the parameter can apply.</p>
    pub fn set_minimum_engine_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.minimum_engine_version = input;
        self
    }
    /// <p>The earliest cache engine version to which the parameter can apply.</p>
    pub fn get_minimum_engine_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.minimum_engine_version
    }
    /// <p>Indicates whether a change to the parameter is applied immediately or requires a reboot for the change to be applied. You can force a reboot or wait until the next maintenance window's reboot. For more information, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/Clusters.Rebooting.html">Rebooting a Cluster</a>.</p>
    pub fn change_type(mut self, input: crate::types::ChangeType) -> Self {
        self.change_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether a change to the parameter is applied immediately or requires a reboot for the change to be applied. You can force a reboot or wait until the next maintenance window's reboot. For more information, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/Clusters.Rebooting.html">Rebooting a Cluster</a>.</p>
    pub fn set_change_type(mut self, input: ::std::option::Option<crate::types::ChangeType>) -> Self {
        self.change_type = input;
        self
    }
    /// <p>Indicates whether a change to the parameter is applied immediately or requires a reboot for the change to be applied. You can force a reboot or wait until the next maintenance window's reboot. For more information, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/Clusters.Rebooting.html">Rebooting a Cluster</a>.</p>
    pub fn get_change_type(&self) -> &::std::option::Option<crate::types::ChangeType> {
        &self.change_type
    }
    /// Consumes the builder and constructs a [`Parameter`](crate::types::Parameter).
    pub fn build(self) -> crate::types::Parameter {
        crate::types::Parameter {
            parameter_name: self.parameter_name,
            parameter_value: self.parameter_value,
            description: self.description,
            source: self.source,
            data_type: self.data_type,
            allowed_values: self.allowed_values,
            is_modifiable: self.is_modifiable,
            minimum_engine_version: self.minimum_engine_version,
            change_type: self.change_type,
        }
    }
}
