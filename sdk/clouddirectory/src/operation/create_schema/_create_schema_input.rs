// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateSchemaInput {
    /// <p>The name that is associated with the schema. This is unique to each account and in each region.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl CreateSchemaInput {
    /// <p>The name that is associated with the schema. This is unique to each account and in each region.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl CreateSchemaInput {
    /// Creates a new builder-style object to manufacture [`CreateSchemaInput`](crate::operation::create_schema::CreateSchemaInput).
    pub fn builder() -> crate::operation::create_schema::builders::CreateSchemaInputBuilder {
        crate::operation::create_schema::builders::CreateSchemaInputBuilder::default()
    }
}

/// A builder for [`CreateSchemaInput`](crate::operation::create_schema::CreateSchemaInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateSchemaInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl CreateSchemaInputBuilder {
    /// <p>The name that is associated with the schema. This is unique to each account and in each region.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name that is associated with the schema. This is unique to each account and in each region.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name that is associated with the schema. This is unique to each account and in each region.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`CreateSchemaInput`](crate::operation::create_schema::CreateSchemaInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_schema::CreateSchemaInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_schema::CreateSchemaInput { name: self.name })
    }
}
