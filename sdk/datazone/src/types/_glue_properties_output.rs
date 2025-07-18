// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The properties of the Amazon Web Services Glue connection.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GluePropertiesOutput {
    /// <p>The status of a connection.</p>
    pub status: ::std::option::Option<crate::types::ConnectionStatus>,
    /// <p>The error message generated if the action is not completed successfully.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
}
impl GluePropertiesOutput {
    /// <p>The status of a connection.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ConnectionStatus> {
        self.status.as_ref()
    }
    /// <p>The error message generated if the action is not completed successfully.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
}
impl GluePropertiesOutput {
    /// Creates a new builder-style object to manufacture [`GluePropertiesOutput`](crate::types::GluePropertiesOutput).
    pub fn builder() -> crate::types::builders::GluePropertiesOutputBuilder {
        crate::types::builders::GluePropertiesOutputBuilder::default()
    }
}

/// A builder for [`GluePropertiesOutput`](crate::types::GluePropertiesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GluePropertiesOutputBuilder {
    pub(crate) status: ::std::option::Option<crate::types::ConnectionStatus>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
}
impl GluePropertiesOutputBuilder {
    /// <p>The status of a connection.</p>
    pub fn status(mut self, input: crate::types::ConnectionStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of a connection.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ConnectionStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of a connection.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ConnectionStatus> {
        &self.status
    }
    /// <p>The error message generated if the action is not completed successfully.</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error message generated if the action is not completed successfully.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>The error message generated if the action is not completed successfully.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// Consumes the builder and constructs a [`GluePropertiesOutput`](crate::types::GluePropertiesOutput).
    pub fn build(self) -> crate::types::GluePropertiesOutput {
        crate::types::GluePropertiesOutput {
            status: self.status,
            error_message: self.error_message,
        }
    }
}
