// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Maps attributes or field names of the documents synced from the data source to Amazon Kendra index field names. You can set up field mappings for each data source when calling <a href="https://docs.aws.amazon.com/kendra/latest/APIReference/API_CreateDataSource.html">CreateDataSource</a> or <a href="https://docs.aws.amazon.com/kendra/latest/APIReference/API_UpdateDataSource.html">UpdateDataSource</a> API. To create custom fields, use the <code>UpdateIndex</code> API to first create an index field and then map to the data source field. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/field-mapping.html">Mapping data source fields</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataSourceToIndexFieldMapping {
    /// <p>The name of the field in the data source. You must first create the index field using the <code>UpdateIndex</code> API.</p>
    pub data_source_field_name: ::std::string::String,
    /// <p>The format for date fields in the data source. If the field specified in <code>DataSourceFieldName</code> is a date field, you must specify the date format. If the field is not a date field, an exception is thrown.</p>
    pub date_field_format: ::std::option::Option<::std::string::String>,
    /// <p>The name of the index field to map to the data source field. The index field type must match the data source field type.</p>
    pub index_field_name: ::std::string::String,
}
impl DataSourceToIndexFieldMapping {
    /// <p>The name of the field in the data source. You must first create the index field using the <code>UpdateIndex</code> API.</p>
    pub fn data_source_field_name(&self) -> &str {
        use std::ops::Deref;
        self.data_source_field_name.deref()
    }
    /// <p>The format for date fields in the data source. If the field specified in <code>DataSourceFieldName</code> is a date field, you must specify the date format. If the field is not a date field, an exception is thrown.</p>
    pub fn date_field_format(&self) -> ::std::option::Option<&str> {
        self.date_field_format.as_deref()
    }
    /// <p>The name of the index field to map to the data source field. The index field type must match the data source field type.</p>
    pub fn index_field_name(&self) -> &str {
        use std::ops::Deref;
        self.index_field_name.deref()
    }
}
impl DataSourceToIndexFieldMapping {
    /// Creates a new builder-style object to manufacture [`DataSourceToIndexFieldMapping`](crate::types::DataSourceToIndexFieldMapping).
    pub fn builder() -> crate::types::builders::DataSourceToIndexFieldMappingBuilder {
        crate::types::builders::DataSourceToIndexFieldMappingBuilder::default()
    }
}

/// A builder for [`DataSourceToIndexFieldMapping`](crate::types::DataSourceToIndexFieldMapping).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataSourceToIndexFieldMappingBuilder {
    pub(crate) data_source_field_name: ::std::option::Option<::std::string::String>,
    pub(crate) date_field_format: ::std::option::Option<::std::string::String>,
    pub(crate) index_field_name: ::std::option::Option<::std::string::String>,
}
impl DataSourceToIndexFieldMappingBuilder {
    /// <p>The name of the field in the data source. You must first create the index field using the <code>UpdateIndex</code> API.</p>
    /// This field is required.
    pub fn data_source_field_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_source_field_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the field in the data source. You must first create the index field using the <code>UpdateIndex</code> API.</p>
    pub fn set_data_source_field_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_source_field_name = input;
        self
    }
    /// <p>The name of the field in the data source. You must first create the index field using the <code>UpdateIndex</code> API.</p>
    pub fn get_data_source_field_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_source_field_name
    }
    /// <p>The format for date fields in the data source. If the field specified in <code>DataSourceFieldName</code> is a date field, you must specify the date format. If the field is not a date field, an exception is thrown.</p>
    pub fn date_field_format(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.date_field_format = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The format for date fields in the data source. If the field specified in <code>DataSourceFieldName</code> is a date field, you must specify the date format. If the field is not a date field, an exception is thrown.</p>
    pub fn set_date_field_format(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.date_field_format = input;
        self
    }
    /// <p>The format for date fields in the data source. If the field specified in <code>DataSourceFieldName</code> is a date field, you must specify the date format. If the field is not a date field, an exception is thrown.</p>
    pub fn get_date_field_format(&self) -> &::std::option::Option<::std::string::String> {
        &self.date_field_format
    }
    /// <p>The name of the index field to map to the data source field. The index field type must match the data source field type.</p>
    /// This field is required.
    pub fn index_field_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.index_field_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the index field to map to the data source field. The index field type must match the data source field type.</p>
    pub fn set_index_field_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.index_field_name = input;
        self
    }
    /// <p>The name of the index field to map to the data source field. The index field type must match the data source field type.</p>
    pub fn get_index_field_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.index_field_name
    }
    /// Consumes the builder and constructs a [`DataSourceToIndexFieldMapping`](crate::types::DataSourceToIndexFieldMapping).
    /// This method will fail if any of the following fields are not set:
    /// - [`data_source_field_name`](crate::types::builders::DataSourceToIndexFieldMappingBuilder::data_source_field_name)
    /// - [`index_field_name`](crate::types::builders::DataSourceToIndexFieldMappingBuilder::index_field_name)
    pub fn build(self) -> ::std::result::Result<crate::types::DataSourceToIndexFieldMapping, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DataSourceToIndexFieldMapping {
            data_source_field_name: self.data_source_field_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "data_source_field_name",
                    "data_source_field_name was not specified but it is required when building DataSourceToIndexFieldMapping",
                )
            })?,
            date_field_format: self.date_field_format,
            index_field_name: self.index_field_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "index_field_name",
                    "index_field_name was not specified but it is required when building DataSourceToIndexFieldMapping",
                )
            })?,
        })
    }
}
