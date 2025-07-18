// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The dataset field details.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataLakeDatasetSchemaField {
    /// <p>The dataset field name.</p>
    pub name: ::std::string::String,
    /// <p>The dataset field type.</p>
    pub r#type: crate::types::DataLakeDatasetSchemaFieldType,
    /// <p>Indicate if the field is required or not.</p>
    pub is_required: bool,
}
impl DataLakeDatasetSchemaField {
    /// <p>The dataset field name.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The dataset field type.</p>
    pub fn r#type(&self) -> &crate::types::DataLakeDatasetSchemaFieldType {
        &self.r#type
    }
    /// <p>Indicate if the field is required or not.</p>
    pub fn is_required(&self) -> bool {
        self.is_required
    }
}
impl DataLakeDatasetSchemaField {
    /// Creates a new builder-style object to manufacture [`DataLakeDatasetSchemaField`](crate::types::DataLakeDatasetSchemaField).
    pub fn builder() -> crate::types::builders::DataLakeDatasetSchemaFieldBuilder {
        crate::types::builders::DataLakeDatasetSchemaFieldBuilder::default()
    }
}

/// A builder for [`DataLakeDatasetSchemaField`](crate::types::DataLakeDatasetSchemaField).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataLakeDatasetSchemaFieldBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::DataLakeDatasetSchemaFieldType>,
    pub(crate) is_required: ::std::option::Option<bool>,
}
impl DataLakeDatasetSchemaFieldBuilder {
    /// <p>The dataset field name.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The dataset field name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The dataset field name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The dataset field type.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::DataLakeDatasetSchemaFieldType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The dataset field type.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::DataLakeDatasetSchemaFieldType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The dataset field type.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::DataLakeDatasetSchemaFieldType> {
        &self.r#type
    }
    /// <p>Indicate if the field is required or not.</p>
    /// This field is required.
    pub fn is_required(mut self, input: bool) -> Self {
        self.is_required = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicate if the field is required or not.</p>
    pub fn set_is_required(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_required = input;
        self
    }
    /// <p>Indicate if the field is required or not.</p>
    pub fn get_is_required(&self) -> &::std::option::Option<bool> {
        &self.is_required
    }
    /// Consumes the builder and constructs a [`DataLakeDatasetSchemaField`](crate::types::DataLakeDatasetSchemaField).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::DataLakeDatasetSchemaFieldBuilder::name)
    /// - [`r#type`](crate::types::builders::DataLakeDatasetSchemaFieldBuilder::type)
    /// - [`is_required`](crate::types::builders::DataLakeDatasetSchemaFieldBuilder::is_required)
    pub fn build(self) -> ::std::result::Result<crate::types::DataLakeDatasetSchemaField, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DataLakeDatasetSchemaField {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building DataLakeDatasetSchemaField",
                )
            })?,
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building DataLakeDatasetSchemaField",
                )
            })?,
            is_required: self.is_required.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "is_required",
                    "is_required was not specified but it is required when building DataLakeDatasetSchemaField",
                )
            })?,
        })
    }
}
