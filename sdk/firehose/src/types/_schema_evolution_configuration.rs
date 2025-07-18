// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration to enable schema evolution.</p>
/// <p>Amazon Data Firehose is in preview release and is subject to change.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SchemaEvolutionConfiguration {
    /// <p>Specify whether you want to enable schema evolution.</p>
    /// <p>Amazon Data Firehose is in preview release and is subject to change.</p>
    pub enabled: bool,
}
impl SchemaEvolutionConfiguration {
    /// <p>Specify whether you want to enable schema evolution.</p>
    /// <p>Amazon Data Firehose is in preview release and is subject to change.</p>
    pub fn enabled(&self) -> bool {
        self.enabled
    }
}
impl SchemaEvolutionConfiguration {
    /// Creates a new builder-style object to manufacture [`SchemaEvolutionConfiguration`](crate::types::SchemaEvolutionConfiguration).
    pub fn builder() -> crate::types::builders::SchemaEvolutionConfigurationBuilder {
        crate::types::builders::SchemaEvolutionConfigurationBuilder::default()
    }
}

/// A builder for [`SchemaEvolutionConfiguration`](crate::types::SchemaEvolutionConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SchemaEvolutionConfigurationBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
}
impl SchemaEvolutionConfigurationBuilder {
    /// <p>Specify whether you want to enable schema evolution.</p>
    /// <p>Amazon Data Firehose is in preview release and is subject to change.</p>
    /// This field is required.
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify whether you want to enable schema evolution.</p>
    /// <p>Amazon Data Firehose is in preview release and is subject to change.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>Specify whether you want to enable schema evolution.</p>
    /// <p>Amazon Data Firehose is in preview release and is subject to change.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// Consumes the builder and constructs a [`SchemaEvolutionConfiguration`](crate::types::SchemaEvolutionConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`enabled`](crate::types::builders::SchemaEvolutionConfigurationBuilder::enabled)
    pub fn build(self) -> ::std::result::Result<crate::types::SchemaEvolutionConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SchemaEvolutionConfiguration {
            enabled: self.enabled.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "enabled",
                    "enabled was not specified but it is required when building SchemaEvolutionConfiguration",
                )
            })?,
        })
    }
}
