// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteConnectionAliasInput {
    /// <p>The identifier of the connection alias to delete.</p>
    pub alias_id: ::std::option::Option<::std::string::String>,
}
impl DeleteConnectionAliasInput {
    /// <p>The identifier of the connection alias to delete.</p>
    pub fn alias_id(&self) -> ::std::option::Option<&str> {
        self.alias_id.as_deref()
    }
}
impl DeleteConnectionAliasInput {
    /// Creates a new builder-style object to manufacture [`DeleteConnectionAliasInput`](crate::operation::delete_connection_alias::DeleteConnectionAliasInput).
    pub fn builder() -> crate::operation::delete_connection_alias::builders::DeleteConnectionAliasInputBuilder {
        crate::operation::delete_connection_alias::builders::DeleteConnectionAliasInputBuilder::default()
    }
}

/// A builder for [`DeleteConnectionAliasInput`](crate::operation::delete_connection_alias::DeleteConnectionAliasInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteConnectionAliasInputBuilder {
    pub(crate) alias_id: ::std::option::Option<::std::string::String>,
}
impl DeleteConnectionAliasInputBuilder {
    /// <p>The identifier of the connection alias to delete.</p>
    /// This field is required.
    pub fn alias_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.alias_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the connection alias to delete.</p>
    pub fn set_alias_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.alias_id = input;
        self
    }
    /// <p>The identifier of the connection alias to delete.</p>
    pub fn get_alias_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.alias_id
    }
    /// Consumes the builder and constructs a [`DeleteConnectionAliasInput`](crate::operation::delete_connection_alias::DeleteConnectionAliasInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_connection_alias::DeleteConnectionAliasInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_connection_alias::DeleteConnectionAliasInput { alias_id: self.alias_id })
    }
}
