// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a parameter used to provision a product.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProvisioningArtifactParameter {
    /// <p>The parameter key.</p>
    pub parameter_key: ::std::option::Option<::std::string::String>,
    /// <p>The default value.</p>
    pub default_value: ::std::option::Option<::std::string::String>,
    /// <p>The parameter type.</p>
    pub parameter_type: ::std::option::Option<::std::string::String>,
    /// <p>If this value is true, the value for this parameter is obfuscated from view when the parameter is retrieved. This parameter is used to hide sensitive information.</p>
    pub is_no_echo: bool,
    /// <p>The description of the parameter.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Constraints that the administrator has put on a parameter.</p>
    pub parameter_constraints: ::std::option::Option<crate::types::ParameterConstraints>,
}
impl ProvisioningArtifactParameter {
    /// <p>The parameter key.</p>
    pub fn parameter_key(&self) -> ::std::option::Option<&str> {
        self.parameter_key.as_deref()
    }
    /// <p>The default value.</p>
    pub fn default_value(&self) -> ::std::option::Option<&str> {
        self.default_value.as_deref()
    }
    /// <p>The parameter type.</p>
    pub fn parameter_type(&self) -> ::std::option::Option<&str> {
        self.parameter_type.as_deref()
    }
    /// <p>If this value is true, the value for this parameter is obfuscated from view when the parameter is retrieved. This parameter is used to hide sensitive information.</p>
    pub fn is_no_echo(&self) -> bool {
        self.is_no_echo
    }
    /// <p>The description of the parameter.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Constraints that the administrator has put on a parameter.</p>
    pub fn parameter_constraints(&self) -> ::std::option::Option<&crate::types::ParameterConstraints> {
        self.parameter_constraints.as_ref()
    }
}
impl ProvisioningArtifactParameter {
    /// Creates a new builder-style object to manufacture [`ProvisioningArtifactParameter`](crate::types::ProvisioningArtifactParameter).
    pub fn builder() -> crate::types::builders::ProvisioningArtifactParameterBuilder {
        crate::types::builders::ProvisioningArtifactParameterBuilder::default()
    }
}

/// A builder for [`ProvisioningArtifactParameter`](crate::types::ProvisioningArtifactParameter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProvisioningArtifactParameterBuilder {
    pub(crate) parameter_key: ::std::option::Option<::std::string::String>,
    pub(crate) default_value: ::std::option::Option<::std::string::String>,
    pub(crate) parameter_type: ::std::option::Option<::std::string::String>,
    pub(crate) is_no_echo: ::std::option::Option<bool>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) parameter_constraints: ::std::option::Option<crate::types::ParameterConstraints>,
}
impl ProvisioningArtifactParameterBuilder {
    /// <p>The parameter key.</p>
    pub fn parameter_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parameter_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The parameter key.</p>
    pub fn set_parameter_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parameter_key = input;
        self
    }
    /// <p>The parameter key.</p>
    pub fn get_parameter_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.parameter_key
    }
    /// <p>The default value.</p>
    pub fn default_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.default_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The default value.</p>
    pub fn set_default_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.default_value = input;
        self
    }
    /// <p>The default value.</p>
    pub fn get_default_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.default_value
    }
    /// <p>The parameter type.</p>
    pub fn parameter_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parameter_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The parameter type.</p>
    pub fn set_parameter_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parameter_type = input;
        self
    }
    /// <p>The parameter type.</p>
    pub fn get_parameter_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.parameter_type
    }
    /// <p>If this value is true, the value for this parameter is obfuscated from view when the parameter is retrieved. This parameter is used to hide sensitive information.</p>
    pub fn is_no_echo(mut self, input: bool) -> Self {
        self.is_no_echo = ::std::option::Option::Some(input);
        self
    }
    /// <p>If this value is true, the value for this parameter is obfuscated from view when the parameter is retrieved. This parameter is used to hide sensitive information.</p>
    pub fn set_is_no_echo(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_no_echo = input;
        self
    }
    /// <p>If this value is true, the value for this parameter is obfuscated from view when the parameter is retrieved. This parameter is used to hide sensitive information.</p>
    pub fn get_is_no_echo(&self) -> &::std::option::Option<bool> {
        &self.is_no_echo
    }
    /// <p>The description of the parameter.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the parameter.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the parameter.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Constraints that the administrator has put on a parameter.</p>
    pub fn parameter_constraints(mut self, input: crate::types::ParameterConstraints) -> Self {
        self.parameter_constraints = ::std::option::Option::Some(input);
        self
    }
    /// <p>Constraints that the administrator has put on a parameter.</p>
    pub fn set_parameter_constraints(mut self, input: ::std::option::Option<crate::types::ParameterConstraints>) -> Self {
        self.parameter_constraints = input;
        self
    }
    /// <p>Constraints that the administrator has put on a parameter.</p>
    pub fn get_parameter_constraints(&self) -> &::std::option::Option<crate::types::ParameterConstraints> {
        &self.parameter_constraints
    }
    /// Consumes the builder and constructs a [`ProvisioningArtifactParameter`](crate::types::ProvisioningArtifactParameter).
    pub fn build(self) -> crate::types::ProvisioningArtifactParameter {
        crate::types::ProvisioningArtifactParameter {
            parameter_key: self.parameter_key,
            default_value: self.default_value,
            parameter_type: self.parameter_type,
            is_no_echo: self.is_no_echo.unwrap_or_default(),
            description: self.description,
            parameter_constraints: self.parameter_constraints,
        }
    }
}
