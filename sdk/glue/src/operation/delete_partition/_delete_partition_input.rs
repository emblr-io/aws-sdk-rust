// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeletePartitionInput {
    /// <p>The ID of the Data Catalog where the partition to be deleted resides. If none is provided, the Amazon Web Services account ID is used by default.</p>
    pub catalog_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the catalog database in which the table in question resides.</p>
    pub database_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the table that contains the partition to be deleted.</p>
    pub table_name: ::std::option::Option<::std::string::String>,
    /// <p>The values that define the partition.</p>
    pub partition_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DeletePartitionInput {
    /// <p>The ID of the Data Catalog where the partition to be deleted resides. If none is provided, the Amazon Web Services account ID is used by default.</p>
    pub fn catalog_id(&self) -> ::std::option::Option<&str> {
        self.catalog_id.as_deref()
    }
    /// <p>The name of the catalog database in which the table in question resides.</p>
    pub fn database_name(&self) -> ::std::option::Option<&str> {
        self.database_name.as_deref()
    }
    /// <p>The name of the table that contains the partition to be deleted.</p>
    pub fn table_name(&self) -> ::std::option::Option<&str> {
        self.table_name.as_deref()
    }
    /// <p>The values that define the partition.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.partition_values.is_none()`.
    pub fn partition_values(&self) -> &[::std::string::String] {
        self.partition_values.as_deref().unwrap_or_default()
    }
}
impl DeletePartitionInput {
    /// Creates a new builder-style object to manufacture [`DeletePartitionInput`](crate::operation::delete_partition::DeletePartitionInput).
    pub fn builder() -> crate::operation::delete_partition::builders::DeletePartitionInputBuilder {
        crate::operation::delete_partition::builders::DeletePartitionInputBuilder::default()
    }
}

/// A builder for [`DeletePartitionInput`](crate::operation::delete_partition::DeletePartitionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeletePartitionInputBuilder {
    pub(crate) catalog_id: ::std::option::Option<::std::string::String>,
    pub(crate) database_name: ::std::option::Option<::std::string::String>,
    pub(crate) table_name: ::std::option::Option<::std::string::String>,
    pub(crate) partition_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DeletePartitionInputBuilder {
    /// <p>The ID of the Data Catalog where the partition to be deleted resides. If none is provided, the Amazon Web Services account ID is used by default.</p>
    pub fn catalog_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Data Catalog where the partition to be deleted resides. If none is provided, the Amazon Web Services account ID is used by default.</p>
    pub fn set_catalog_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog_id = input;
        self
    }
    /// <p>The ID of the Data Catalog where the partition to be deleted resides. If none is provided, the Amazon Web Services account ID is used by default.</p>
    pub fn get_catalog_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog_id
    }
    /// <p>The name of the catalog database in which the table in question resides.</p>
    /// This field is required.
    pub fn database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the catalog database in which the table in question resides.</p>
    pub fn set_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database_name = input;
        self
    }
    /// <p>The name of the catalog database in which the table in question resides.</p>
    pub fn get_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.database_name
    }
    /// <p>The name of the table that contains the partition to be deleted.</p>
    /// This field is required.
    pub fn table_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the table that contains the partition to be deleted.</p>
    pub fn set_table_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_name = input;
        self
    }
    /// <p>The name of the table that contains the partition to be deleted.</p>
    pub fn get_table_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_name
    }
    /// Appends an item to `partition_values`.
    ///
    /// To override the contents of this collection use [`set_partition_values`](Self::set_partition_values).
    ///
    /// <p>The values that define the partition.</p>
    pub fn partition_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.partition_values.unwrap_or_default();
        v.push(input.into());
        self.partition_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The values that define the partition.</p>
    pub fn set_partition_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.partition_values = input;
        self
    }
    /// <p>The values that define the partition.</p>
    pub fn get_partition_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.partition_values
    }
    /// Consumes the builder and constructs a [`DeletePartitionInput`](crate::operation::delete_partition::DeletePartitionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_partition::DeletePartitionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_partition::DeletePartitionInput {
            catalog_id: self.catalog_id,
            database_name: self.database_name,
            table_name: self.table_name,
            partition_values: self.partition_values,
        })
    }
}
