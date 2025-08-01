// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies a target that uses Oracle SQL.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OracleSqlCatalogTarget {
    /// <p>The name of the data target.</p>
    pub name: ::std::string::String,
    /// <p>The nodes that are inputs to the data target.</p>
    pub inputs: ::std::vec::Vec<::std::string::String>,
    /// <p>The name of the database to write to.</p>
    pub database: ::std::string::String,
    /// <p>The name of the table in the database to write to.</p>
    pub table: ::std::string::String,
}
impl OracleSqlCatalogTarget {
    /// <p>The name of the data target.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The nodes that are inputs to the data target.</p>
    pub fn inputs(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.inputs.deref()
    }
    /// <p>The name of the database to write to.</p>
    pub fn database(&self) -> &str {
        use std::ops::Deref;
        self.database.deref()
    }
    /// <p>The name of the table in the database to write to.</p>
    pub fn table(&self) -> &str {
        use std::ops::Deref;
        self.table.deref()
    }
}
impl OracleSqlCatalogTarget {
    /// Creates a new builder-style object to manufacture [`OracleSqlCatalogTarget`](crate::types::OracleSqlCatalogTarget).
    pub fn builder() -> crate::types::builders::OracleSqlCatalogTargetBuilder {
        crate::types::builders::OracleSqlCatalogTargetBuilder::default()
    }
}

/// A builder for [`OracleSqlCatalogTarget`](crate::types::OracleSqlCatalogTarget).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OracleSqlCatalogTargetBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) inputs: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) database: ::std::option::Option<::std::string::String>,
    pub(crate) table: ::std::option::Option<::std::string::String>,
}
impl OracleSqlCatalogTargetBuilder {
    /// <p>The name of the data target.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the data target.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the data target.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `inputs`.
    ///
    /// To override the contents of this collection use [`set_inputs`](Self::set_inputs).
    ///
    /// <p>The nodes that are inputs to the data target.</p>
    pub fn inputs(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.inputs.unwrap_or_default();
        v.push(input.into());
        self.inputs = ::std::option::Option::Some(v);
        self
    }
    /// <p>The nodes that are inputs to the data target.</p>
    pub fn set_inputs(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.inputs = input;
        self
    }
    /// <p>The nodes that are inputs to the data target.</p>
    pub fn get_inputs(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.inputs
    }
    /// <p>The name of the database to write to.</p>
    /// This field is required.
    pub fn database(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the database to write to.</p>
    pub fn set_database(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database = input;
        self
    }
    /// <p>The name of the database to write to.</p>
    pub fn get_database(&self) -> &::std::option::Option<::std::string::String> {
        &self.database
    }
    /// <p>The name of the table in the database to write to.</p>
    /// This field is required.
    pub fn table(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the table in the database to write to.</p>
    pub fn set_table(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table = input;
        self
    }
    /// <p>The name of the table in the database to write to.</p>
    pub fn get_table(&self) -> &::std::option::Option<::std::string::String> {
        &self.table
    }
    /// Consumes the builder and constructs a [`OracleSqlCatalogTarget`](crate::types::OracleSqlCatalogTarget).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::OracleSqlCatalogTargetBuilder::name)
    /// - [`inputs`](crate::types::builders::OracleSqlCatalogTargetBuilder::inputs)
    /// - [`database`](crate::types::builders::OracleSqlCatalogTargetBuilder::database)
    /// - [`table`](crate::types::builders::OracleSqlCatalogTargetBuilder::table)
    pub fn build(self) -> ::std::result::Result<crate::types::OracleSqlCatalogTarget, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::OracleSqlCatalogTarget {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building OracleSqlCatalogTarget",
                )
            })?,
            inputs: self.inputs.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "inputs",
                    "inputs was not specified but it is required when building OracleSqlCatalogTarget",
                )
            })?,
            database: self.database.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "database",
                    "database was not specified but it is required when building OracleSqlCatalogTarget",
                )
            })?,
            table: self.table.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "table",
                    "table was not specified but it is required when building OracleSqlCatalogTarget",
                )
            })?,
        })
    }
}
