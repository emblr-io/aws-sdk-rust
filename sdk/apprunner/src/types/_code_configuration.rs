// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the configuration that App Runner uses to build and run an App Runner service from a source code repository.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CodeConfiguration {
    /// <p>The source of the App Runner configuration. Values are interpreted as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>REPOSITORY</code> – App Runner reads configuration values from the <code>apprunner.yaml</code> file in the source code repository and ignores <code>CodeConfigurationValues</code>.</p></li>
    /// <li>
    /// <p><code>API</code> – App Runner uses configuration values provided in <code>CodeConfigurationValues</code> and ignores the <code>apprunner.yaml</code> file in the source code repository.</p></li>
    /// </ul>
    pub configuration_source: crate::types::ConfigurationSource,
    /// <p>The basic configuration for building and running the App Runner service. Use it to quickly launch an App Runner service without providing a <code>apprunner.yaml</code> file in the source code repository (or ignoring the file if it exists).</p>
    pub code_configuration_values: ::std::option::Option<crate::types::CodeConfigurationValues>,
}
impl CodeConfiguration {
    /// <p>The source of the App Runner configuration. Values are interpreted as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>REPOSITORY</code> – App Runner reads configuration values from the <code>apprunner.yaml</code> file in the source code repository and ignores <code>CodeConfigurationValues</code>.</p></li>
    /// <li>
    /// <p><code>API</code> – App Runner uses configuration values provided in <code>CodeConfigurationValues</code> and ignores the <code>apprunner.yaml</code> file in the source code repository.</p></li>
    /// </ul>
    pub fn configuration_source(&self) -> &crate::types::ConfigurationSource {
        &self.configuration_source
    }
    /// <p>The basic configuration for building and running the App Runner service. Use it to quickly launch an App Runner service without providing a <code>apprunner.yaml</code> file in the source code repository (or ignoring the file if it exists).</p>
    pub fn code_configuration_values(&self) -> ::std::option::Option<&crate::types::CodeConfigurationValues> {
        self.code_configuration_values.as_ref()
    }
}
impl CodeConfiguration {
    /// Creates a new builder-style object to manufacture [`CodeConfiguration`](crate::types::CodeConfiguration).
    pub fn builder() -> crate::types::builders::CodeConfigurationBuilder {
        crate::types::builders::CodeConfigurationBuilder::default()
    }
}

/// A builder for [`CodeConfiguration`](crate::types::CodeConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CodeConfigurationBuilder {
    pub(crate) configuration_source: ::std::option::Option<crate::types::ConfigurationSource>,
    pub(crate) code_configuration_values: ::std::option::Option<crate::types::CodeConfigurationValues>,
}
impl CodeConfigurationBuilder {
    /// <p>The source of the App Runner configuration. Values are interpreted as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>REPOSITORY</code> – App Runner reads configuration values from the <code>apprunner.yaml</code> file in the source code repository and ignores <code>CodeConfigurationValues</code>.</p></li>
    /// <li>
    /// <p><code>API</code> – App Runner uses configuration values provided in <code>CodeConfigurationValues</code> and ignores the <code>apprunner.yaml</code> file in the source code repository.</p></li>
    /// </ul>
    /// This field is required.
    pub fn configuration_source(mut self, input: crate::types::ConfigurationSource) -> Self {
        self.configuration_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>The source of the App Runner configuration. Values are interpreted as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>REPOSITORY</code> – App Runner reads configuration values from the <code>apprunner.yaml</code> file in the source code repository and ignores <code>CodeConfigurationValues</code>.</p></li>
    /// <li>
    /// <p><code>API</code> – App Runner uses configuration values provided in <code>CodeConfigurationValues</code> and ignores the <code>apprunner.yaml</code> file in the source code repository.</p></li>
    /// </ul>
    pub fn set_configuration_source(mut self, input: ::std::option::Option<crate::types::ConfigurationSource>) -> Self {
        self.configuration_source = input;
        self
    }
    /// <p>The source of the App Runner configuration. Values are interpreted as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>REPOSITORY</code> – App Runner reads configuration values from the <code>apprunner.yaml</code> file in the source code repository and ignores <code>CodeConfigurationValues</code>.</p></li>
    /// <li>
    /// <p><code>API</code> – App Runner uses configuration values provided in <code>CodeConfigurationValues</code> and ignores the <code>apprunner.yaml</code> file in the source code repository.</p></li>
    /// </ul>
    pub fn get_configuration_source(&self) -> &::std::option::Option<crate::types::ConfigurationSource> {
        &self.configuration_source
    }
    /// <p>The basic configuration for building and running the App Runner service. Use it to quickly launch an App Runner service without providing a <code>apprunner.yaml</code> file in the source code repository (or ignoring the file if it exists).</p>
    pub fn code_configuration_values(mut self, input: crate::types::CodeConfigurationValues) -> Self {
        self.code_configuration_values = ::std::option::Option::Some(input);
        self
    }
    /// <p>The basic configuration for building and running the App Runner service. Use it to quickly launch an App Runner service without providing a <code>apprunner.yaml</code> file in the source code repository (or ignoring the file if it exists).</p>
    pub fn set_code_configuration_values(mut self, input: ::std::option::Option<crate::types::CodeConfigurationValues>) -> Self {
        self.code_configuration_values = input;
        self
    }
    /// <p>The basic configuration for building and running the App Runner service. Use it to quickly launch an App Runner service without providing a <code>apprunner.yaml</code> file in the source code repository (or ignoring the file if it exists).</p>
    pub fn get_code_configuration_values(&self) -> &::std::option::Option<crate::types::CodeConfigurationValues> {
        &self.code_configuration_values
    }
    /// Consumes the builder and constructs a [`CodeConfiguration`](crate::types::CodeConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`configuration_source`](crate::types::builders::CodeConfigurationBuilder::configuration_source)
    pub fn build(self) -> ::std::result::Result<crate::types::CodeConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CodeConfiguration {
            configuration_source: self.configuration_source.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "configuration_source",
                    "configuration_source was not specified but it is required when building CodeConfiguration",
                )
            })?,
            code_configuration_values: self.code_configuration_values,
        })
    }
}
