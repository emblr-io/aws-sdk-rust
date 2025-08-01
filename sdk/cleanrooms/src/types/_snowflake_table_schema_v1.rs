// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Snowflake table schema.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SnowflakeTableSchemaV1 {
    /// <p>The column name.</p>
    pub column_name: ::std::string::String,
    /// <p>The column's data type. Supported data types: <code>ARRAY</code>, <code>BIGINT</code>, <code>BOOLEAN</code>, <code>CHAR</code>, <code>DATE</code>, <code>DECIMAL</code>, <code>DOUBLE</code>, <code>DOUBLE PRECISION</code>, <code>FLOAT</code>, <code>FLOAT4</code>, <code>INT</code>, <code>INTEGER</code>, <code>MAP</code>, <code>NUMERIC</code>, <code>NUMBER</code>, <code>REAL</code>, <code>SMALLINT</code>, <code>STRING</code>, <code>TIMESTAMP</code>, <code>TIMESTAMP_LTZ</code>, <code>TIMESTAMP_NTZ</code>, <code>DATETIME</code>, <code>TINYINT</code>, <code>VARCHAR</code>, <code>TEXT</code>, <code>CHARACTER</code>.</p>
    pub column_type: ::std::string::String,
}
impl SnowflakeTableSchemaV1 {
    /// <p>The column name.</p>
    pub fn column_name(&self) -> &str {
        use std::ops::Deref;
        self.column_name.deref()
    }
    /// <p>The column's data type. Supported data types: <code>ARRAY</code>, <code>BIGINT</code>, <code>BOOLEAN</code>, <code>CHAR</code>, <code>DATE</code>, <code>DECIMAL</code>, <code>DOUBLE</code>, <code>DOUBLE PRECISION</code>, <code>FLOAT</code>, <code>FLOAT4</code>, <code>INT</code>, <code>INTEGER</code>, <code>MAP</code>, <code>NUMERIC</code>, <code>NUMBER</code>, <code>REAL</code>, <code>SMALLINT</code>, <code>STRING</code>, <code>TIMESTAMP</code>, <code>TIMESTAMP_LTZ</code>, <code>TIMESTAMP_NTZ</code>, <code>DATETIME</code>, <code>TINYINT</code>, <code>VARCHAR</code>, <code>TEXT</code>, <code>CHARACTER</code>.</p>
    pub fn column_type(&self) -> &str {
        use std::ops::Deref;
        self.column_type.deref()
    }
}
impl SnowflakeTableSchemaV1 {
    /// Creates a new builder-style object to manufacture [`SnowflakeTableSchemaV1`](crate::types::SnowflakeTableSchemaV1).
    pub fn builder() -> crate::types::builders::SnowflakeTableSchemaV1Builder {
        crate::types::builders::SnowflakeTableSchemaV1Builder::default()
    }
}

/// A builder for [`SnowflakeTableSchemaV1`](crate::types::SnowflakeTableSchemaV1).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SnowflakeTableSchemaV1Builder {
    pub(crate) column_name: ::std::option::Option<::std::string::String>,
    pub(crate) column_type: ::std::option::Option<::std::string::String>,
}
impl SnowflakeTableSchemaV1Builder {
    /// <p>The column name.</p>
    /// This field is required.
    pub fn column_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.column_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The column name.</p>
    pub fn set_column_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.column_name = input;
        self
    }
    /// <p>The column name.</p>
    pub fn get_column_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.column_name
    }
    /// <p>The column's data type. Supported data types: <code>ARRAY</code>, <code>BIGINT</code>, <code>BOOLEAN</code>, <code>CHAR</code>, <code>DATE</code>, <code>DECIMAL</code>, <code>DOUBLE</code>, <code>DOUBLE PRECISION</code>, <code>FLOAT</code>, <code>FLOAT4</code>, <code>INT</code>, <code>INTEGER</code>, <code>MAP</code>, <code>NUMERIC</code>, <code>NUMBER</code>, <code>REAL</code>, <code>SMALLINT</code>, <code>STRING</code>, <code>TIMESTAMP</code>, <code>TIMESTAMP_LTZ</code>, <code>TIMESTAMP_NTZ</code>, <code>DATETIME</code>, <code>TINYINT</code>, <code>VARCHAR</code>, <code>TEXT</code>, <code>CHARACTER</code>.</p>
    /// This field is required.
    pub fn column_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.column_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The column's data type. Supported data types: <code>ARRAY</code>, <code>BIGINT</code>, <code>BOOLEAN</code>, <code>CHAR</code>, <code>DATE</code>, <code>DECIMAL</code>, <code>DOUBLE</code>, <code>DOUBLE PRECISION</code>, <code>FLOAT</code>, <code>FLOAT4</code>, <code>INT</code>, <code>INTEGER</code>, <code>MAP</code>, <code>NUMERIC</code>, <code>NUMBER</code>, <code>REAL</code>, <code>SMALLINT</code>, <code>STRING</code>, <code>TIMESTAMP</code>, <code>TIMESTAMP_LTZ</code>, <code>TIMESTAMP_NTZ</code>, <code>DATETIME</code>, <code>TINYINT</code>, <code>VARCHAR</code>, <code>TEXT</code>, <code>CHARACTER</code>.</p>
    pub fn set_column_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.column_type = input;
        self
    }
    /// <p>The column's data type. Supported data types: <code>ARRAY</code>, <code>BIGINT</code>, <code>BOOLEAN</code>, <code>CHAR</code>, <code>DATE</code>, <code>DECIMAL</code>, <code>DOUBLE</code>, <code>DOUBLE PRECISION</code>, <code>FLOAT</code>, <code>FLOAT4</code>, <code>INT</code>, <code>INTEGER</code>, <code>MAP</code>, <code>NUMERIC</code>, <code>NUMBER</code>, <code>REAL</code>, <code>SMALLINT</code>, <code>STRING</code>, <code>TIMESTAMP</code>, <code>TIMESTAMP_LTZ</code>, <code>TIMESTAMP_NTZ</code>, <code>DATETIME</code>, <code>TINYINT</code>, <code>VARCHAR</code>, <code>TEXT</code>, <code>CHARACTER</code>.</p>
    pub fn get_column_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.column_type
    }
    /// Consumes the builder and constructs a [`SnowflakeTableSchemaV1`](crate::types::SnowflakeTableSchemaV1).
    /// This method will fail if any of the following fields are not set:
    /// - [`column_name`](crate::types::builders::SnowflakeTableSchemaV1Builder::column_name)
    /// - [`column_type`](crate::types::builders::SnowflakeTableSchemaV1Builder::column_type)
    pub fn build(self) -> ::std::result::Result<crate::types::SnowflakeTableSchemaV1, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SnowflakeTableSchemaV1 {
            column_name: self.column_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "column_name",
                    "column_name was not specified but it is required when building SnowflakeTableSchemaV1",
                )
            })?,
            column_type: self.column_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "column_type",
                    "column_type was not specified but it is required when building SnowflakeTableSchemaV1",
                )
            })?,
        })
    }
}
