// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetConnectorDestinationInput {
    /// <p>The identifier of the C2C connector destination.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
}
impl GetConnectorDestinationInput {
    /// <p>The identifier of the C2C connector destination.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
}
impl GetConnectorDestinationInput {
    /// Creates a new builder-style object to manufacture [`GetConnectorDestinationInput`](crate::operation::get_connector_destination::GetConnectorDestinationInput).
    pub fn builder() -> crate::operation::get_connector_destination::builders::GetConnectorDestinationInputBuilder {
        crate::operation::get_connector_destination::builders::GetConnectorDestinationInputBuilder::default()
    }
}

/// A builder for [`GetConnectorDestinationInput`](crate::operation::get_connector_destination::GetConnectorDestinationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetConnectorDestinationInputBuilder {
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
}
impl GetConnectorDestinationInputBuilder {
    /// <p>The identifier of the C2C connector destination.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the C2C connector destination.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The identifier of the C2C connector destination.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Consumes the builder and constructs a [`GetConnectorDestinationInput`](crate::operation::get_connector_destination::GetConnectorDestinationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_connector_destination::GetConnectorDestinationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_connector_destination::GetConnectorDestinationInput { identifier: self.identifier })
    }
}
