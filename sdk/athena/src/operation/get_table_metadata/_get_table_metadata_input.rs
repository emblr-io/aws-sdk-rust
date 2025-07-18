// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTableMetadataInput {
    /// <p>The name of the data catalog that contains the database and table metadata to return.</p>
    pub catalog_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the database that contains the table metadata to return.</p>
    pub database_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the table for which metadata is returned.</p>
    pub table_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the workgroup for which the metadata is being fetched. Required if requesting an IAM Identity Center enabled Glue Data Catalog.</p>
    pub work_group: ::std::option::Option<::std::string::String>,
}
impl GetTableMetadataInput {
    /// <p>The name of the data catalog that contains the database and table metadata to return.</p>
    pub fn catalog_name(&self) -> ::std::option::Option<&str> {
        self.catalog_name.as_deref()
    }
    /// <p>The name of the database that contains the table metadata to return.</p>
    pub fn database_name(&self) -> ::std::option::Option<&str> {
        self.database_name.as_deref()
    }
    /// <p>The name of the table for which metadata is returned.</p>
    pub fn table_name(&self) -> ::std::option::Option<&str> {
        self.table_name.as_deref()
    }
    /// <p>The name of the workgroup for which the metadata is being fetched. Required if requesting an IAM Identity Center enabled Glue Data Catalog.</p>
    pub fn work_group(&self) -> ::std::option::Option<&str> {
        self.work_group.as_deref()
    }
}
impl GetTableMetadataInput {
    /// Creates a new builder-style object to manufacture [`GetTableMetadataInput`](crate::operation::get_table_metadata::GetTableMetadataInput).
    pub fn builder() -> crate::operation::get_table_metadata::builders::GetTableMetadataInputBuilder {
        crate::operation::get_table_metadata::builders::GetTableMetadataInputBuilder::default()
    }
}

/// A builder for [`GetTableMetadataInput`](crate::operation::get_table_metadata::GetTableMetadataInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTableMetadataInputBuilder {
    pub(crate) catalog_name: ::std::option::Option<::std::string::String>,
    pub(crate) database_name: ::std::option::Option<::std::string::String>,
    pub(crate) table_name: ::std::option::Option<::std::string::String>,
    pub(crate) work_group: ::std::option::Option<::std::string::String>,
}
impl GetTableMetadataInputBuilder {
    /// <p>The name of the data catalog that contains the database and table metadata to return.</p>
    /// This field is required.
    pub fn catalog_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the data catalog that contains the database and table metadata to return.</p>
    pub fn set_catalog_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog_name = input;
        self
    }
    /// <p>The name of the data catalog that contains the database and table metadata to return.</p>
    pub fn get_catalog_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog_name
    }
    /// <p>The name of the database that contains the table metadata to return.</p>
    /// This field is required.
    pub fn database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the database that contains the table metadata to return.</p>
    pub fn set_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database_name = input;
        self
    }
    /// <p>The name of the database that contains the table metadata to return.</p>
    pub fn get_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.database_name
    }
    /// <p>The name of the table for which metadata is returned.</p>
    /// This field is required.
    pub fn table_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the table for which metadata is returned.</p>
    pub fn set_table_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_name = input;
        self
    }
    /// <p>The name of the table for which metadata is returned.</p>
    pub fn get_table_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_name
    }
    /// <p>The name of the workgroup for which the metadata is being fetched. Required if requesting an IAM Identity Center enabled Glue Data Catalog.</p>
    pub fn work_group(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.work_group = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the workgroup for which the metadata is being fetched. Required if requesting an IAM Identity Center enabled Glue Data Catalog.</p>
    pub fn set_work_group(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.work_group = input;
        self
    }
    /// <p>The name of the workgroup for which the metadata is being fetched. Required if requesting an IAM Identity Center enabled Glue Data Catalog.</p>
    pub fn get_work_group(&self) -> &::std::option::Option<::std::string::String> {
        &self.work_group
    }
    /// Consumes the builder and constructs a [`GetTableMetadataInput`](crate::operation::get_table_metadata::GetTableMetadataInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_table_metadata::GetTableMetadataInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_table_metadata::GetTableMetadataInput {
            catalog_name: self.catalog_name,
            database_name: self.database_name,
            table_name: self.table_name,
            work_group: self.work_group,
        })
    }
}
