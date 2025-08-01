// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateConnectorDefinitionInput {
    /// The ID of the connector definition.
    pub connector_definition_id: ::std::option::Option<::std::string::String>,
    /// The name of the definition.
    pub name: ::std::option::Option<::std::string::String>,
}
impl UpdateConnectorDefinitionInput {
    /// The ID of the connector definition.
    pub fn connector_definition_id(&self) -> ::std::option::Option<&str> {
        self.connector_definition_id.as_deref()
    }
    /// The name of the definition.
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl UpdateConnectorDefinitionInput {
    /// Creates a new builder-style object to manufacture [`UpdateConnectorDefinitionInput`](crate::operation::update_connector_definition::UpdateConnectorDefinitionInput).
    pub fn builder() -> crate::operation::update_connector_definition::builders::UpdateConnectorDefinitionInputBuilder {
        crate::operation::update_connector_definition::builders::UpdateConnectorDefinitionInputBuilder::default()
    }
}

/// A builder for [`UpdateConnectorDefinitionInput`](crate::operation::update_connector_definition::UpdateConnectorDefinitionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateConnectorDefinitionInputBuilder {
    pub(crate) connector_definition_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl UpdateConnectorDefinitionInputBuilder {
    /// The ID of the connector definition.
    /// This field is required.
    pub fn connector_definition_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connector_definition_id = ::std::option::Option::Some(input.into());
        self
    }
    /// The ID of the connector definition.
    pub fn set_connector_definition_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connector_definition_id = input;
        self
    }
    /// The ID of the connector definition.
    pub fn get_connector_definition_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.connector_definition_id
    }
    /// The name of the definition.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// The name of the definition.
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// The name of the definition.
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`UpdateConnectorDefinitionInput`](crate::operation::update_connector_definition::UpdateConnectorDefinitionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_connector_definition::UpdateConnectorDefinitionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_connector_definition::UpdateConnectorDefinitionInput {
            connector_definition_id: self.connector_definition_id,
            name: self.name,
        })
    }
}
