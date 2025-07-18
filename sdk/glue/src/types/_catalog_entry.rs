// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies a table definition in the Glue Data Catalog.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CatalogEntry {
    /// <p>The database in which the table metadata resides.</p>
    pub database_name: ::std::string::String,
    /// <p>The name of the table in question.</p>
    pub table_name: ::std::string::String,
}
impl CatalogEntry {
    /// <p>The database in which the table metadata resides.</p>
    pub fn database_name(&self) -> &str {
        use std::ops::Deref;
        self.database_name.deref()
    }
    /// <p>The name of the table in question.</p>
    pub fn table_name(&self) -> &str {
        use std::ops::Deref;
        self.table_name.deref()
    }
}
impl CatalogEntry {
    /// Creates a new builder-style object to manufacture [`CatalogEntry`](crate::types::CatalogEntry).
    pub fn builder() -> crate::types::builders::CatalogEntryBuilder {
        crate::types::builders::CatalogEntryBuilder::default()
    }
}

/// A builder for [`CatalogEntry`](crate::types::CatalogEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CatalogEntryBuilder {
    pub(crate) database_name: ::std::option::Option<::std::string::String>,
    pub(crate) table_name: ::std::option::Option<::std::string::String>,
}
impl CatalogEntryBuilder {
    /// <p>The database in which the table metadata resides.</p>
    /// This field is required.
    pub fn database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The database in which the table metadata resides.</p>
    pub fn set_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database_name = input;
        self
    }
    /// <p>The database in which the table metadata resides.</p>
    pub fn get_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.database_name
    }
    /// <p>The name of the table in question.</p>
    /// This field is required.
    pub fn table_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the table in question.</p>
    pub fn set_table_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_name = input;
        self
    }
    /// <p>The name of the table in question.</p>
    pub fn get_table_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_name
    }
    /// Consumes the builder and constructs a [`CatalogEntry`](crate::types::CatalogEntry).
    /// This method will fail if any of the following fields are not set:
    /// - [`database_name`](crate::types::builders::CatalogEntryBuilder::database_name)
    /// - [`table_name`](crate::types::builders::CatalogEntryBuilder::table_name)
    pub fn build(self) -> ::std::result::Result<crate::types::CatalogEntry, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CatalogEntry {
            database_name: self.database_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "database_name",
                    "database_name was not specified but it is required when building CatalogEntry",
                )
            })?,
            table_name: self.table_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "table_name",
                    "table_name was not specified but it is required when building CatalogEntry",
                )
            })?,
        })
    }
}
