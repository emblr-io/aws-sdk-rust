// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteDataMigrationInput {
    /// <p>The identifier (name or ARN) of the data migration to delete.</p>
    pub data_migration_identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteDataMigrationInput {
    /// <p>The identifier (name or ARN) of the data migration to delete.</p>
    pub fn data_migration_identifier(&self) -> ::std::option::Option<&str> {
        self.data_migration_identifier.as_deref()
    }
}
impl DeleteDataMigrationInput {
    /// Creates a new builder-style object to manufacture [`DeleteDataMigrationInput`](crate::operation::delete_data_migration::DeleteDataMigrationInput).
    pub fn builder() -> crate::operation::delete_data_migration::builders::DeleteDataMigrationInputBuilder {
        crate::operation::delete_data_migration::builders::DeleteDataMigrationInputBuilder::default()
    }
}

/// A builder for [`DeleteDataMigrationInput`](crate::operation::delete_data_migration::DeleteDataMigrationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteDataMigrationInputBuilder {
    pub(crate) data_migration_identifier: ::std::option::Option<::std::string::String>,
}
impl DeleteDataMigrationInputBuilder {
    /// <p>The identifier (name or ARN) of the data migration to delete.</p>
    /// This field is required.
    pub fn data_migration_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_migration_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier (name or ARN) of the data migration to delete.</p>
    pub fn set_data_migration_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_migration_identifier = input;
        self
    }
    /// <p>The identifier (name or ARN) of the data migration to delete.</p>
    pub fn get_data_migration_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_migration_identifier
    }
    /// Consumes the builder and constructs a [`DeleteDataMigrationInput`](crate::operation::delete_data_migration::DeleteDataMigrationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_data_migration::DeleteDataMigrationInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_data_migration::DeleteDataMigrationInput {
            data_migration_identifier: self.data_migration_identifier,
        })
    }
}
