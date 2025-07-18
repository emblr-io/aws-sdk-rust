// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateColumnStatisticsForTableInput {
    /// <p>The ID of the Data Catalog where the partitions in question reside. If none is supplied, the Amazon Web Services account ID is used by default.</p>
    pub catalog_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the catalog database where the partitions reside.</p>
    pub database_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the partitions' table.</p>
    pub table_name: ::std::option::Option<::std::string::String>,
    /// <p>A list of the column statistics.</p>
    pub column_statistics_list: ::std::option::Option<::std::vec::Vec<crate::types::ColumnStatistics>>,
}
impl UpdateColumnStatisticsForTableInput {
    /// <p>The ID of the Data Catalog where the partitions in question reside. If none is supplied, the Amazon Web Services account ID is used by default.</p>
    pub fn catalog_id(&self) -> ::std::option::Option<&str> {
        self.catalog_id.as_deref()
    }
    /// <p>The name of the catalog database where the partitions reside.</p>
    pub fn database_name(&self) -> ::std::option::Option<&str> {
        self.database_name.as_deref()
    }
    /// <p>The name of the partitions' table.</p>
    pub fn table_name(&self) -> ::std::option::Option<&str> {
        self.table_name.as_deref()
    }
    /// <p>A list of the column statistics.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.column_statistics_list.is_none()`.
    pub fn column_statistics_list(&self) -> &[crate::types::ColumnStatistics] {
        self.column_statistics_list.as_deref().unwrap_or_default()
    }
}
impl UpdateColumnStatisticsForTableInput {
    /// Creates a new builder-style object to manufacture [`UpdateColumnStatisticsForTableInput`](crate::operation::update_column_statistics_for_table::UpdateColumnStatisticsForTableInput).
    pub fn builder() -> crate::operation::update_column_statistics_for_table::builders::UpdateColumnStatisticsForTableInputBuilder {
        crate::operation::update_column_statistics_for_table::builders::UpdateColumnStatisticsForTableInputBuilder::default()
    }
}

/// A builder for [`UpdateColumnStatisticsForTableInput`](crate::operation::update_column_statistics_for_table::UpdateColumnStatisticsForTableInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateColumnStatisticsForTableInputBuilder {
    pub(crate) catalog_id: ::std::option::Option<::std::string::String>,
    pub(crate) database_name: ::std::option::Option<::std::string::String>,
    pub(crate) table_name: ::std::option::Option<::std::string::String>,
    pub(crate) column_statistics_list: ::std::option::Option<::std::vec::Vec<crate::types::ColumnStatistics>>,
}
impl UpdateColumnStatisticsForTableInputBuilder {
    /// <p>The ID of the Data Catalog where the partitions in question reside. If none is supplied, the Amazon Web Services account ID is used by default.</p>
    pub fn catalog_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Data Catalog where the partitions in question reside. If none is supplied, the Amazon Web Services account ID is used by default.</p>
    pub fn set_catalog_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog_id = input;
        self
    }
    /// <p>The ID of the Data Catalog where the partitions in question reside. If none is supplied, the Amazon Web Services account ID is used by default.</p>
    pub fn get_catalog_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog_id
    }
    /// <p>The name of the catalog database where the partitions reside.</p>
    /// This field is required.
    pub fn database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the catalog database where the partitions reside.</p>
    pub fn set_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database_name = input;
        self
    }
    /// <p>The name of the catalog database where the partitions reside.</p>
    pub fn get_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.database_name
    }
    /// <p>The name of the partitions' table.</p>
    /// This field is required.
    pub fn table_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the partitions' table.</p>
    pub fn set_table_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_name = input;
        self
    }
    /// <p>The name of the partitions' table.</p>
    pub fn get_table_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_name
    }
    /// Appends an item to `column_statistics_list`.
    ///
    /// To override the contents of this collection use [`set_column_statistics_list`](Self::set_column_statistics_list).
    ///
    /// <p>A list of the column statistics.</p>
    pub fn column_statistics_list(mut self, input: crate::types::ColumnStatistics) -> Self {
        let mut v = self.column_statistics_list.unwrap_or_default();
        v.push(input);
        self.column_statistics_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the column statistics.</p>
    pub fn set_column_statistics_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ColumnStatistics>>) -> Self {
        self.column_statistics_list = input;
        self
    }
    /// <p>A list of the column statistics.</p>
    pub fn get_column_statistics_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ColumnStatistics>> {
        &self.column_statistics_list
    }
    /// Consumes the builder and constructs a [`UpdateColumnStatisticsForTableInput`](crate::operation::update_column_statistics_for_table::UpdateColumnStatisticsForTableInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_column_statistics_for_table::UpdateColumnStatisticsForTableInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::update_column_statistics_for_table::UpdateColumnStatisticsForTableInput {
                catalog_id: self.catalog_id,
                database_name: self.database_name,
                table_name: self.table_name,
                column_statistics_list: self.column_statistics_list,
            },
        )
    }
}
