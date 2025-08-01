// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The environment configuration user parameters.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct EnvironmentConfigurationUserParameter {
    /// <p>The ID of the environment.</p>
    pub environment_id: ::std::option::Option<::std::string::String>,
    /// <p>The environment configuration name.</p>
    pub environment_configuration_name: ::std::option::Option<::std::string::String>,
    /// <p>The environment parameters.</p>
    pub environment_parameters: ::std::option::Option<::std::vec::Vec<crate::types::EnvironmentParameter>>,
}
impl EnvironmentConfigurationUserParameter {
    /// <p>The ID of the environment.</p>
    pub fn environment_id(&self) -> ::std::option::Option<&str> {
        self.environment_id.as_deref()
    }
    /// <p>The environment configuration name.</p>
    pub fn environment_configuration_name(&self) -> ::std::option::Option<&str> {
        self.environment_configuration_name.as_deref()
    }
    /// <p>The environment parameters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.environment_parameters.is_none()`.
    pub fn environment_parameters(&self) -> &[crate::types::EnvironmentParameter] {
        self.environment_parameters.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for EnvironmentConfigurationUserParameter {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("EnvironmentConfigurationUserParameter");
        formatter.field("environment_id", &self.environment_id);
        formatter.field("environment_configuration_name", &"*** Sensitive Data Redacted ***");
        formatter.field("environment_parameters", &self.environment_parameters);
        formatter.finish()
    }
}
impl EnvironmentConfigurationUserParameter {
    /// Creates a new builder-style object to manufacture [`EnvironmentConfigurationUserParameter`](crate::types::EnvironmentConfigurationUserParameter).
    pub fn builder() -> crate::types::builders::EnvironmentConfigurationUserParameterBuilder {
        crate::types::builders::EnvironmentConfigurationUserParameterBuilder::default()
    }
}

/// A builder for [`EnvironmentConfigurationUserParameter`](crate::types::EnvironmentConfigurationUserParameter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct EnvironmentConfigurationUserParameterBuilder {
    pub(crate) environment_id: ::std::option::Option<::std::string::String>,
    pub(crate) environment_configuration_name: ::std::option::Option<::std::string::String>,
    pub(crate) environment_parameters: ::std::option::Option<::std::vec::Vec<crate::types::EnvironmentParameter>>,
}
impl EnvironmentConfigurationUserParameterBuilder {
    /// <p>The ID of the environment.</p>
    pub fn environment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the environment.</p>
    pub fn set_environment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_id = input;
        self
    }
    /// <p>The ID of the environment.</p>
    pub fn get_environment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_id
    }
    /// <p>The environment configuration name.</p>
    pub fn environment_configuration_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_configuration_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The environment configuration name.</p>
    pub fn set_environment_configuration_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_configuration_name = input;
        self
    }
    /// <p>The environment configuration name.</p>
    pub fn get_environment_configuration_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_configuration_name
    }
    /// Appends an item to `environment_parameters`.
    ///
    /// To override the contents of this collection use [`set_environment_parameters`](Self::set_environment_parameters).
    ///
    /// <p>The environment parameters.</p>
    pub fn environment_parameters(mut self, input: crate::types::EnvironmentParameter) -> Self {
        let mut v = self.environment_parameters.unwrap_or_default();
        v.push(input);
        self.environment_parameters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The environment parameters.</p>
    pub fn set_environment_parameters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EnvironmentParameter>>) -> Self {
        self.environment_parameters = input;
        self
    }
    /// <p>The environment parameters.</p>
    pub fn get_environment_parameters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EnvironmentParameter>> {
        &self.environment_parameters
    }
    /// Consumes the builder and constructs a [`EnvironmentConfigurationUserParameter`](crate::types::EnvironmentConfigurationUserParameter).
    pub fn build(self) -> crate::types::EnvironmentConfigurationUserParameter {
        crate::types::EnvironmentConfigurationUserParameter {
            environment_id: self.environment_id,
            environment_configuration_name: self.environment_configuration_name,
            environment_parameters: self.environment_parameters,
        }
    }
}
impl ::std::fmt::Debug for EnvironmentConfigurationUserParameterBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("EnvironmentConfigurationUserParameterBuilder");
        formatter.field("environment_id", &self.environment_id);
        formatter.field("environment_configuration_name", &"*** Sensitive Data Redacted ***");
        formatter.field("environment_parameters", &self.environment_parameters);
        formatter.finish()
    }
}
