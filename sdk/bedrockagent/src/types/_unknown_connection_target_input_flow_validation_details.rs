// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about an unknown target input for a connection.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UnknownConnectionTargetInputFlowValidationDetails {
    /// <p>The name of the connection with the unknown target input.</p>
    pub connection: ::std::string::String,
}
impl UnknownConnectionTargetInputFlowValidationDetails {
    /// <p>The name of the connection with the unknown target input.</p>
    pub fn connection(&self) -> &str {
        use std::ops::Deref;
        self.connection.deref()
    }
}
impl UnknownConnectionTargetInputFlowValidationDetails {
    /// Creates a new builder-style object to manufacture [`UnknownConnectionTargetInputFlowValidationDetails`](crate::types::UnknownConnectionTargetInputFlowValidationDetails).
    pub fn builder() -> crate::types::builders::UnknownConnectionTargetInputFlowValidationDetailsBuilder {
        crate::types::builders::UnknownConnectionTargetInputFlowValidationDetailsBuilder::default()
    }
}

/// A builder for [`UnknownConnectionTargetInputFlowValidationDetails`](crate::types::UnknownConnectionTargetInputFlowValidationDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UnknownConnectionTargetInputFlowValidationDetailsBuilder {
    pub(crate) connection: ::std::option::Option<::std::string::String>,
}
impl UnknownConnectionTargetInputFlowValidationDetailsBuilder {
    /// <p>The name of the connection with the unknown target input.</p>
    /// This field is required.
    pub fn connection(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the connection with the unknown target input.</p>
    pub fn set_connection(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection = input;
        self
    }
    /// <p>The name of the connection with the unknown target input.</p>
    pub fn get_connection(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection
    }
    /// Consumes the builder and constructs a [`UnknownConnectionTargetInputFlowValidationDetails`](crate::types::UnknownConnectionTargetInputFlowValidationDetails).
    /// This method will fail if any of the following fields are not set:
    /// - [`connection`](crate::types::builders::UnknownConnectionTargetInputFlowValidationDetailsBuilder::connection)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::UnknownConnectionTargetInputFlowValidationDetails, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::types::UnknownConnectionTargetInputFlowValidationDetails {
            connection: self.connection.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "connection",
                    "connection was not specified but it is required when building UnknownConnectionTargetInputFlowValidationDetails",
                )
            })?,
        })
    }
}
