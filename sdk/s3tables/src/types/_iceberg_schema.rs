// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details about the schema for an Iceberg table.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IcebergSchema {
    /// <p>The schema fields for the table</p>
    pub fields: ::std::vec::Vec<crate::types::SchemaField>,
}
impl IcebergSchema {
    /// <p>The schema fields for the table</p>
    pub fn fields(&self) -> &[crate::types::SchemaField] {
        use std::ops::Deref;
        self.fields.deref()
    }
}
impl IcebergSchema {
    /// Creates a new builder-style object to manufacture [`IcebergSchema`](crate::types::IcebergSchema).
    pub fn builder() -> crate::types::builders::IcebergSchemaBuilder {
        crate::types::builders::IcebergSchemaBuilder::default()
    }
}

/// A builder for [`IcebergSchema`](crate::types::IcebergSchema).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IcebergSchemaBuilder {
    pub(crate) fields: ::std::option::Option<::std::vec::Vec<crate::types::SchemaField>>,
}
impl IcebergSchemaBuilder {
    /// Appends an item to `fields`.
    ///
    /// To override the contents of this collection use [`set_fields`](Self::set_fields).
    ///
    /// <p>The schema fields for the table</p>
    pub fn fields(mut self, input: crate::types::SchemaField) -> Self {
        let mut v = self.fields.unwrap_or_default();
        v.push(input);
        self.fields = ::std::option::Option::Some(v);
        self
    }
    /// <p>The schema fields for the table</p>
    pub fn set_fields(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SchemaField>>) -> Self {
        self.fields = input;
        self
    }
    /// <p>The schema fields for the table</p>
    pub fn get_fields(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SchemaField>> {
        &self.fields
    }
    /// Consumes the builder and constructs a [`IcebergSchema`](crate::types::IcebergSchema).
    /// This method will fail if any of the following fields are not set:
    /// - [`fields`](crate::types::builders::IcebergSchemaBuilder::fields)
    pub fn build(self) -> ::std::result::Result<crate::types::IcebergSchema, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::IcebergSchema {
            fields: self.fields.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "fields",
                    "fields was not specified but it is required when building IcebergSchema",
                )
            })?,
        })
    }
}
