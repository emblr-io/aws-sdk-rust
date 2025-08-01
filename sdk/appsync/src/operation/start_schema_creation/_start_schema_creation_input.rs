// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartSchemaCreationInput {
    /// <p>The API ID.</p>
    pub api_id: ::std::option::Option<::std::string::String>,
    /// <p>The schema definition, in GraphQL schema language format.</p>
    pub definition: ::std::option::Option<::aws_smithy_types::Blob>,
}
impl StartSchemaCreationInput {
    /// <p>The API ID.</p>
    pub fn api_id(&self) -> ::std::option::Option<&str> {
        self.api_id.as_deref()
    }
    /// <p>The schema definition, in GraphQL schema language format.</p>
    pub fn definition(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.definition.as_ref()
    }
}
impl StartSchemaCreationInput {
    /// Creates a new builder-style object to manufacture [`StartSchemaCreationInput`](crate::operation::start_schema_creation::StartSchemaCreationInput).
    pub fn builder() -> crate::operation::start_schema_creation::builders::StartSchemaCreationInputBuilder {
        crate::operation::start_schema_creation::builders::StartSchemaCreationInputBuilder::default()
    }
}

/// A builder for [`StartSchemaCreationInput`](crate::operation::start_schema_creation::StartSchemaCreationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartSchemaCreationInputBuilder {
    pub(crate) api_id: ::std::option::Option<::std::string::String>,
    pub(crate) definition: ::std::option::Option<::aws_smithy_types::Blob>,
}
impl StartSchemaCreationInputBuilder {
    /// <p>The API ID.</p>
    /// This field is required.
    pub fn api_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.api_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The API ID.</p>
    pub fn set_api_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.api_id = input;
        self
    }
    /// <p>The API ID.</p>
    pub fn get_api_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.api_id
    }
    /// <p>The schema definition, in GraphQL schema language format.</p>
    /// This field is required.
    pub fn definition(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.definition = ::std::option::Option::Some(input);
        self
    }
    /// <p>The schema definition, in GraphQL schema language format.</p>
    pub fn set_definition(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.definition = input;
        self
    }
    /// <p>The schema definition, in GraphQL schema language format.</p>
    pub fn get_definition(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.definition
    }
    /// Consumes the builder and constructs a [`StartSchemaCreationInput`](crate::operation::start_schema_creation::StartSchemaCreationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_schema_creation::StartSchemaCreationInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::start_schema_creation::StartSchemaCreationInput {
            api_id: self.api_id,
            definition: self.definition,
        })
    }
}
