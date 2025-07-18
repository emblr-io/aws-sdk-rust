// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that describes a security control parameter and the options for customizing it.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ParameterDefinition {
    /// <p>Description of a control parameter.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The options for customizing a control parameter. Customization options vary based on the data type of the parameter.</p>
    pub configuration_options: ::std::option::Option<crate::types::ConfigurationOptions>,
}
impl ParameterDefinition {
    /// <p>Description of a control parameter.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The options for customizing a control parameter. Customization options vary based on the data type of the parameter.</p>
    pub fn configuration_options(&self) -> ::std::option::Option<&crate::types::ConfigurationOptions> {
        self.configuration_options.as_ref()
    }
}
impl ParameterDefinition {
    /// Creates a new builder-style object to manufacture [`ParameterDefinition`](crate::types::ParameterDefinition).
    pub fn builder() -> crate::types::builders::ParameterDefinitionBuilder {
        crate::types::builders::ParameterDefinitionBuilder::default()
    }
}

/// A builder for [`ParameterDefinition`](crate::types::ParameterDefinition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ParameterDefinitionBuilder {
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) configuration_options: ::std::option::Option<crate::types::ConfigurationOptions>,
}
impl ParameterDefinitionBuilder {
    /// <p>Description of a control parameter.</p>
    /// This field is required.
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Description of a control parameter.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>Description of a control parameter.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The options for customizing a control parameter. Customization options vary based on the data type of the parameter.</p>
    /// This field is required.
    pub fn configuration_options(mut self, input: crate::types::ConfigurationOptions) -> Self {
        self.configuration_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The options for customizing a control parameter. Customization options vary based on the data type of the parameter.</p>
    pub fn set_configuration_options(mut self, input: ::std::option::Option<crate::types::ConfigurationOptions>) -> Self {
        self.configuration_options = input;
        self
    }
    /// <p>The options for customizing a control parameter. Customization options vary based on the data type of the parameter.</p>
    pub fn get_configuration_options(&self) -> &::std::option::Option<crate::types::ConfigurationOptions> {
        &self.configuration_options
    }
    /// Consumes the builder and constructs a [`ParameterDefinition`](crate::types::ParameterDefinition).
    pub fn build(self) -> crate::types::ParameterDefinition {
        crate::types::ParameterDefinition {
            description: self.description,
            configuration_options: self.configuration_options,
        }
    }
}
