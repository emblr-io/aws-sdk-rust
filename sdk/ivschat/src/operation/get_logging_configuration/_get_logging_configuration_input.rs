// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetLoggingConfigurationInput {
    /// <p>Identifier of the logging configuration to be retrieved.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
}
impl GetLoggingConfigurationInput {
    /// <p>Identifier of the logging configuration to be retrieved.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
}
impl GetLoggingConfigurationInput {
    /// Creates a new builder-style object to manufacture [`GetLoggingConfigurationInput`](crate::operation::get_logging_configuration::GetLoggingConfigurationInput).
    pub fn builder() -> crate::operation::get_logging_configuration::builders::GetLoggingConfigurationInputBuilder {
        crate::operation::get_logging_configuration::builders::GetLoggingConfigurationInputBuilder::default()
    }
}

/// A builder for [`GetLoggingConfigurationInput`](crate::operation::get_logging_configuration::GetLoggingConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetLoggingConfigurationInputBuilder {
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
}
impl GetLoggingConfigurationInputBuilder {
    /// <p>Identifier of the logging configuration to be retrieved.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifier of the logging configuration to be retrieved.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>Identifier of the logging configuration to be retrieved.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Consumes the builder and constructs a [`GetLoggingConfigurationInput`](crate::operation::get_logging_configuration::GetLoggingConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_logging_configuration::GetLoggingConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_logging_configuration::GetLoggingConfigurationInput { identifier: self.identifier })
    }
}
