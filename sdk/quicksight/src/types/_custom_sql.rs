// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A physical table type built from the results of the custom SQL query.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CustomSql {
    /// <p>The Amazon Resource Name (ARN) of the data source.</p>
    pub data_source_arn: ::std::string::String,
    /// <p>A display name for the SQL query result.</p>
    pub name: ::std::string::String,
    /// <p>The SQL query.</p>
    pub sql_query: ::std::string::String,
    /// <p>The column schema from the SQL query result set.</p>
    pub columns: ::std::option::Option<::std::vec::Vec<crate::types::InputColumn>>,
}
impl CustomSql {
    /// <p>The Amazon Resource Name (ARN) of the data source.</p>
    pub fn data_source_arn(&self) -> &str {
        use std::ops::Deref;
        self.data_source_arn.deref()
    }
    /// <p>A display name for the SQL query result.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The SQL query.</p>
    pub fn sql_query(&self) -> &str {
        use std::ops::Deref;
        self.sql_query.deref()
    }
    /// <p>The column schema from the SQL query result set.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.columns.is_none()`.
    pub fn columns(&self) -> &[crate::types::InputColumn] {
        self.columns.as_deref().unwrap_or_default()
    }
}
impl CustomSql {
    /// Creates a new builder-style object to manufacture [`CustomSql`](crate::types::CustomSql).
    pub fn builder() -> crate::types::builders::CustomSqlBuilder {
        crate::types::builders::CustomSqlBuilder::default()
    }
}

/// A builder for [`CustomSql`](crate::types::CustomSql).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CustomSqlBuilder {
    pub(crate) data_source_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) sql_query: ::std::option::Option<::std::string::String>,
    pub(crate) columns: ::std::option::Option<::std::vec::Vec<crate::types::InputColumn>>,
}
impl CustomSqlBuilder {
    /// <p>The Amazon Resource Name (ARN) of the data source.</p>
    /// This field is required.
    pub fn data_source_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_source_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the data source.</p>
    pub fn set_data_source_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_source_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the data source.</p>
    pub fn get_data_source_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_source_arn
    }
    /// <p>A display name for the SQL query result.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A display name for the SQL query result.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A display name for the SQL query result.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The SQL query.</p>
    /// This field is required.
    pub fn sql_query(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sql_query = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The SQL query.</p>
    pub fn set_sql_query(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sql_query = input;
        self
    }
    /// <p>The SQL query.</p>
    pub fn get_sql_query(&self) -> &::std::option::Option<::std::string::String> {
        &self.sql_query
    }
    /// Appends an item to `columns`.
    ///
    /// To override the contents of this collection use [`set_columns`](Self::set_columns).
    ///
    /// <p>The column schema from the SQL query result set.</p>
    pub fn columns(mut self, input: crate::types::InputColumn) -> Self {
        let mut v = self.columns.unwrap_or_default();
        v.push(input);
        self.columns = ::std::option::Option::Some(v);
        self
    }
    /// <p>The column schema from the SQL query result set.</p>
    pub fn set_columns(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InputColumn>>) -> Self {
        self.columns = input;
        self
    }
    /// <p>The column schema from the SQL query result set.</p>
    pub fn get_columns(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InputColumn>> {
        &self.columns
    }
    /// Consumes the builder and constructs a [`CustomSql`](crate::types::CustomSql).
    /// This method will fail if any of the following fields are not set:
    /// - [`data_source_arn`](crate::types::builders::CustomSqlBuilder::data_source_arn)
    /// - [`name`](crate::types::builders::CustomSqlBuilder::name)
    /// - [`sql_query`](crate::types::builders::CustomSqlBuilder::sql_query)
    pub fn build(self) -> ::std::result::Result<crate::types::CustomSql, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CustomSql {
            data_source_arn: self.data_source_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "data_source_arn",
                    "data_source_arn was not specified but it is required when building CustomSql",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building CustomSql",
                )
            })?,
            sql_query: self.sql_query.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "sql_query",
                    "sql_query was not specified but it is required when building CustomSql",
                )
            })?,
            columns: self.columns,
        })
    }
}
