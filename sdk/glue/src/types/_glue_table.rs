// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The database and table in the Glue Data Catalog that is used for input or output data.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GlueTable {
    /// <p>A database name in the Glue Data Catalog.</p>
    pub database_name: ::std::string::String,
    /// <p>A table name in the Glue Data Catalog.</p>
    pub table_name: ::std::string::String,
    /// <p>A unique identifier for the Glue Data Catalog.</p>
    pub catalog_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the connection to the Glue Data Catalog.</p>
    pub connection_name: ::std::option::Option<::std::string::String>,
    /// <p>Additional options for the table. Currently there are two keys supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>pushDownPredicate</code>: to filter on partitions without having to list and read all the files in your dataset.</p></li>
    /// <li>
    /// <p><code>catalogPartitionPredicate</code>: to use server-side partition pruning using partition indexes in the Glue Data Catalog.</p></li>
    /// </ul>
    pub additional_options: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl GlueTable {
    /// <p>A database name in the Glue Data Catalog.</p>
    pub fn database_name(&self) -> &str {
        use std::ops::Deref;
        self.database_name.deref()
    }
    /// <p>A table name in the Glue Data Catalog.</p>
    pub fn table_name(&self) -> &str {
        use std::ops::Deref;
        self.table_name.deref()
    }
    /// <p>A unique identifier for the Glue Data Catalog.</p>
    pub fn catalog_id(&self) -> ::std::option::Option<&str> {
        self.catalog_id.as_deref()
    }
    /// <p>The name of the connection to the Glue Data Catalog.</p>
    pub fn connection_name(&self) -> ::std::option::Option<&str> {
        self.connection_name.as_deref()
    }
    /// <p>Additional options for the table. Currently there are two keys supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>pushDownPredicate</code>: to filter on partitions without having to list and read all the files in your dataset.</p></li>
    /// <li>
    /// <p><code>catalogPartitionPredicate</code>: to use server-side partition pruning using partition indexes in the Glue Data Catalog.</p></li>
    /// </ul>
    pub fn additional_options(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.additional_options.as_ref()
    }
}
impl GlueTable {
    /// Creates a new builder-style object to manufacture [`GlueTable`](crate::types::GlueTable).
    pub fn builder() -> crate::types::builders::GlueTableBuilder {
        crate::types::builders::GlueTableBuilder::default()
    }
}

/// A builder for [`GlueTable`](crate::types::GlueTable).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GlueTableBuilder {
    pub(crate) database_name: ::std::option::Option<::std::string::String>,
    pub(crate) table_name: ::std::option::Option<::std::string::String>,
    pub(crate) catalog_id: ::std::option::Option<::std::string::String>,
    pub(crate) connection_name: ::std::option::Option<::std::string::String>,
    pub(crate) additional_options: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl GlueTableBuilder {
    /// <p>A database name in the Glue Data Catalog.</p>
    /// This field is required.
    pub fn database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A database name in the Glue Data Catalog.</p>
    pub fn set_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database_name = input;
        self
    }
    /// <p>A database name in the Glue Data Catalog.</p>
    pub fn get_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.database_name
    }
    /// <p>A table name in the Glue Data Catalog.</p>
    /// This field is required.
    pub fn table_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A table name in the Glue Data Catalog.</p>
    pub fn set_table_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_name = input;
        self
    }
    /// <p>A table name in the Glue Data Catalog.</p>
    pub fn get_table_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_name
    }
    /// <p>A unique identifier for the Glue Data Catalog.</p>
    pub fn catalog_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the Glue Data Catalog.</p>
    pub fn set_catalog_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog_id = input;
        self
    }
    /// <p>A unique identifier for the Glue Data Catalog.</p>
    pub fn get_catalog_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog_id
    }
    /// <p>The name of the connection to the Glue Data Catalog.</p>
    pub fn connection_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the connection to the Glue Data Catalog.</p>
    pub fn set_connection_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_name = input;
        self
    }
    /// <p>The name of the connection to the Glue Data Catalog.</p>
    pub fn get_connection_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_name
    }
    /// Adds a key-value pair to `additional_options`.
    ///
    /// To override the contents of this collection use [`set_additional_options`](Self::set_additional_options).
    ///
    /// <p>Additional options for the table. Currently there are two keys supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>pushDownPredicate</code>: to filter on partitions without having to list and read all the files in your dataset.</p></li>
    /// <li>
    /// <p><code>catalogPartitionPredicate</code>: to use server-side partition pruning using partition indexes in the Glue Data Catalog.</p></li>
    /// </ul>
    pub fn additional_options(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.additional_options.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.additional_options = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Additional options for the table. Currently there are two keys supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>pushDownPredicate</code>: to filter on partitions without having to list and read all the files in your dataset.</p></li>
    /// <li>
    /// <p><code>catalogPartitionPredicate</code>: to use server-side partition pruning using partition indexes in the Glue Data Catalog.</p></li>
    /// </ul>
    pub fn set_additional_options(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.additional_options = input;
        self
    }
    /// <p>Additional options for the table. Currently there are two keys supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>pushDownPredicate</code>: to filter on partitions without having to list and read all the files in your dataset.</p></li>
    /// <li>
    /// <p><code>catalogPartitionPredicate</code>: to use server-side partition pruning using partition indexes in the Glue Data Catalog.</p></li>
    /// </ul>
    pub fn get_additional_options(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.additional_options
    }
    /// Consumes the builder and constructs a [`GlueTable`](crate::types::GlueTable).
    /// This method will fail if any of the following fields are not set:
    /// - [`database_name`](crate::types::builders::GlueTableBuilder::database_name)
    /// - [`table_name`](crate::types::builders::GlueTableBuilder::table_name)
    pub fn build(self) -> ::std::result::Result<crate::types::GlueTable, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::GlueTable {
            database_name: self.database_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "database_name",
                    "database_name was not specified but it is required when building GlueTable",
                )
            })?,
            table_name: self.table_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "table_name",
                    "table_name was not specified but it is required when building GlueTable",
                )
            })?,
            catalog_id: self.catalog_id,
            connection_name: self.connection_name,
            additional_options: self.additional_options,
        })
    }
}
