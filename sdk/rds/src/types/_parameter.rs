// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This data type is used as a request parameter in the <code>ModifyDBParameterGroup</code> and <code>ResetDBParameterGroup</code> actions.</p>
/// <p>This data type is used as a response element in the <code>DescribeEngineDefaultParameters</code> and <code>DescribeDBParameters</code> actions.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Parameter {
    /// <p>The name of the parameter.</p>
    pub parameter_name: ::std::option::Option<::std::string::String>,
    /// <p>The value of the parameter.</p>
    pub parameter_value: ::std::option::Option<::std::string::String>,
    /// <p>Provides a description of the parameter.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The source of the parameter value.</p>
    pub source: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the engine specific parameters type.</p>
    pub apply_type: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the valid data type for the parameter.</p>
    pub data_type: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the valid range of values for the parameter.</p>
    pub allowed_values: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether (<code>true</code>) or not (<code>false</code>) the parameter can be modified. Some parameters have security or operational implications that prevent them from being changed.</p>
    pub is_modifiable: ::std::option::Option<bool>,
    /// <p>The earliest engine version to which the parameter can apply.</p>
    pub minimum_engine_version: ::std::option::Option<::std::string::String>,
    /// <p>Indicates when to apply parameter updates.</p>
    pub apply_method: ::std::option::Option<crate::types::ApplyMethod>,
    /// <p>The valid DB engine modes.</p>
    pub supported_engine_modes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
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
    /// <p>Provides a description of the parameter.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The source of the parameter value.</p>
    pub fn source(&self) -> ::std::option::Option<&str> {
        self.source.as_deref()
    }
    /// <p>Specifies the engine specific parameters type.</p>
    pub fn apply_type(&self) -> ::std::option::Option<&str> {
        self.apply_type.as_deref()
    }
    /// <p>Specifies the valid data type for the parameter.</p>
    pub fn data_type(&self) -> ::std::option::Option<&str> {
        self.data_type.as_deref()
    }
    /// <p>Specifies the valid range of values for the parameter.</p>
    pub fn allowed_values(&self) -> ::std::option::Option<&str> {
        self.allowed_values.as_deref()
    }
    /// <p>Indicates whether (<code>true</code>) or not (<code>false</code>) the parameter can be modified. Some parameters have security or operational implications that prevent them from being changed.</p>
    pub fn is_modifiable(&self) -> ::std::option::Option<bool> {
        self.is_modifiable
    }
    /// <p>The earliest engine version to which the parameter can apply.</p>
    pub fn minimum_engine_version(&self) -> ::std::option::Option<&str> {
        self.minimum_engine_version.as_deref()
    }
    /// <p>Indicates when to apply parameter updates.</p>
    pub fn apply_method(&self) -> ::std::option::Option<&crate::types::ApplyMethod> {
        self.apply_method.as_ref()
    }
    /// <p>The valid DB engine modes.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.supported_engine_modes.is_none()`.
    pub fn supported_engine_modes(&self) -> &[::std::string::String] {
        self.supported_engine_modes.as_deref().unwrap_or_default()
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
    pub(crate) apply_type: ::std::option::Option<::std::string::String>,
    pub(crate) data_type: ::std::option::Option<::std::string::String>,
    pub(crate) allowed_values: ::std::option::Option<::std::string::String>,
    pub(crate) is_modifiable: ::std::option::Option<bool>,
    pub(crate) minimum_engine_version: ::std::option::Option<::std::string::String>,
    pub(crate) apply_method: ::std::option::Option<crate::types::ApplyMethod>,
    pub(crate) supported_engine_modes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
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
    /// <p>Provides a description of the parameter.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provides a description of the parameter.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>Provides a description of the parameter.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The source of the parameter value.</p>
    pub fn source(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The source of the parameter value.</p>
    pub fn set_source(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source = input;
        self
    }
    /// <p>The source of the parameter value.</p>
    pub fn get_source(&self) -> &::std::option::Option<::std::string::String> {
        &self.source
    }
    /// <p>Specifies the engine specific parameters type.</p>
    pub fn apply_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.apply_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the engine specific parameters type.</p>
    pub fn set_apply_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.apply_type = input;
        self
    }
    /// <p>Specifies the engine specific parameters type.</p>
    pub fn get_apply_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.apply_type
    }
    /// <p>Specifies the valid data type for the parameter.</p>
    pub fn data_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the valid data type for the parameter.</p>
    pub fn set_data_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_type = input;
        self
    }
    /// <p>Specifies the valid data type for the parameter.</p>
    pub fn get_data_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_type
    }
    /// <p>Specifies the valid range of values for the parameter.</p>
    pub fn allowed_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.allowed_values = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the valid range of values for the parameter.</p>
    pub fn set_allowed_values(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.allowed_values = input;
        self
    }
    /// <p>Specifies the valid range of values for the parameter.</p>
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
    /// <p>The earliest engine version to which the parameter can apply.</p>
    pub fn minimum_engine_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.minimum_engine_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The earliest engine version to which the parameter can apply.</p>
    pub fn set_minimum_engine_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.minimum_engine_version = input;
        self
    }
    /// <p>The earliest engine version to which the parameter can apply.</p>
    pub fn get_minimum_engine_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.minimum_engine_version
    }
    /// <p>Indicates when to apply parameter updates.</p>
    pub fn apply_method(mut self, input: crate::types::ApplyMethod) -> Self {
        self.apply_method = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates when to apply parameter updates.</p>
    pub fn set_apply_method(mut self, input: ::std::option::Option<crate::types::ApplyMethod>) -> Self {
        self.apply_method = input;
        self
    }
    /// <p>Indicates when to apply parameter updates.</p>
    pub fn get_apply_method(&self) -> &::std::option::Option<crate::types::ApplyMethod> {
        &self.apply_method
    }
    /// Appends an item to `supported_engine_modes`.
    ///
    /// To override the contents of this collection use [`set_supported_engine_modes`](Self::set_supported_engine_modes).
    ///
    /// <p>The valid DB engine modes.</p>
    pub fn supported_engine_modes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.supported_engine_modes.unwrap_or_default();
        v.push(input.into());
        self.supported_engine_modes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The valid DB engine modes.</p>
    pub fn set_supported_engine_modes(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.supported_engine_modes = input;
        self
    }
    /// <p>The valid DB engine modes.</p>
    pub fn get_supported_engine_modes(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.supported_engine_modes
    }
    /// Consumes the builder and constructs a [`Parameter`](crate::types::Parameter).
    pub fn build(self) -> crate::types::Parameter {
        crate::types::Parameter {
            parameter_name: self.parameter_name,
            parameter_value: self.parameter_value,
            description: self.description,
            source: self.source,
            apply_type: self.apply_type,
            data_type: self.data_type,
            allowed_values: self.allowed_values,
            is_modifiable: self.is_modifiable,
            minimum_engine_version: self.minimum_engine_version,
            apply_method: self.apply_method,
            supported_engine_modes: self.supported_engine_modes,
        }
    }
}
