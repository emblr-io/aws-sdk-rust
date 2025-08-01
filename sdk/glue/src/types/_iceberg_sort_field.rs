// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines a single field within an Iceberg sort order specification, including the source field, transformation, sort direction, and null value ordering.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IcebergSortField {
    /// <p>The identifier of the source field from the table schema that this sort field is based on.</p>
    pub source_id: i32,
    /// <p>The transformation function applied to the source field before sorting, such as identity, bucket, or truncate.</p>
    pub transform: ::std::string::String,
    /// <p>The sort direction for this field, either ascending or descending.</p>
    pub direction: crate::types::IcebergSortDirection,
    /// <p>The ordering behavior for null values in this field, specifying whether nulls should appear first or last in the sort order.</p>
    pub null_order: crate::types::IcebergNullOrder,
}
impl IcebergSortField {
    /// <p>The identifier of the source field from the table schema that this sort field is based on.</p>
    pub fn source_id(&self) -> i32 {
        self.source_id
    }
    /// <p>The transformation function applied to the source field before sorting, such as identity, bucket, or truncate.</p>
    pub fn transform(&self) -> &str {
        use std::ops::Deref;
        self.transform.deref()
    }
    /// <p>The sort direction for this field, either ascending or descending.</p>
    pub fn direction(&self) -> &crate::types::IcebergSortDirection {
        &self.direction
    }
    /// <p>The ordering behavior for null values in this field, specifying whether nulls should appear first or last in the sort order.</p>
    pub fn null_order(&self) -> &crate::types::IcebergNullOrder {
        &self.null_order
    }
}
impl IcebergSortField {
    /// Creates a new builder-style object to manufacture [`IcebergSortField`](crate::types::IcebergSortField).
    pub fn builder() -> crate::types::builders::IcebergSortFieldBuilder {
        crate::types::builders::IcebergSortFieldBuilder::default()
    }
}

/// A builder for [`IcebergSortField`](crate::types::IcebergSortField).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IcebergSortFieldBuilder {
    pub(crate) source_id: ::std::option::Option<i32>,
    pub(crate) transform: ::std::option::Option<::std::string::String>,
    pub(crate) direction: ::std::option::Option<crate::types::IcebergSortDirection>,
    pub(crate) null_order: ::std::option::Option<crate::types::IcebergNullOrder>,
}
impl IcebergSortFieldBuilder {
    /// <p>The identifier of the source field from the table schema that this sort field is based on.</p>
    /// This field is required.
    pub fn source_id(mut self, input: i32) -> Self {
        self.source_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The identifier of the source field from the table schema that this sort field is based on.</p>
    pub fn set_source_id(mut self, input: ::std::option::Option<i32>) -> Self {
        self.source_id = input;
        self
    }
    /// <p>The identifier of the source field from the table schema that this sort field is based on.</p>
    pub fn get_source_id(&self) -> &::std::option::Option<i32> {
        &self.source_id
    }
    /// <p>The transformation function applied to the source field before sorting, such as identity, bucket, or truncate.</p>
    /// This field is required.
    pub fn transform(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.transform = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The transformation function applied to the source field before sorting, such as identity, bucket, or truncate.</p>
    pub fn set_transform(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.transform = input;
        self
    }
    /// <p>The transformation function applied to the source field before sorting, such as identity, bucket, or truncate.</p>
    pub fn get_transform(&self) -> &::std::option::Option<::std::string::String> {
        &self.transform
    }
    /// <p>The sort direction for this field, either ascending or descending.</p>
    /// This field is required.
    pub fn direction(mut self, input: crate::types::IcebergSortDirection) -> Self {
        self.direction = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sort direction for this field, either ascending or descending.</p>
    pub fn set_direction(mut self, input: ::std::option::Option<crate::types::IcebergSortDirection>) -> Self {
        self.direction = input;
        self
    }
    /// <p>The sort direction for this field, either ascending or descending.</p>
    pub fn get_direction(&self) -> &::std::option::Option<crate::types::IcebergSortDirection> {
        &self.direction
    }
    /// <p>The ordering behavior for null values in this field, specifying whether nulls should appear first or last in the sort order.</p>
    /// This field is required.
    pub fn null_order(mut self, input: crate::types::IcebergNullOrder) -> Self {
        self.null_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ordering behavior for null values in this field, specifying whether nulls should appear first or last in the sort order.</p>
    pub fn set_null_order(mut self, input: ::std::option::Option<crate::types::IcebergNullOrder>) -> Self {
        self.null_order = input;
        self
    }
    /// <p>The ordering behavior for null values in this field, specifying whether nulls should appear first or last in the sort order.</p>
    pub fn get_null_order(&self) -> &::std::option::Option<crate::types::IcebergNullOrder> {
        &self.null_order
    }
    /// Consumes the builder and constructs a [`IcebergSortField`](crate::types::IcebergSortField).
    /// This method will fail if any of the following fields are not set:
    /// - [`transform`](crate::types::builders::IcebergSortFieldBuilder::transform)
    /// - [`direction`](crate::types::builders::IcebergSortFieldBuilder::direction)
    /// - [`null_order`](crate::types::builders::IcebergSortFieldBuilder::null_order)
    pub fn build(self) -> ::std::result::Result<crate::types::IcebergSortField, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::IcebergSortField {
            source_id: self.source_id.unwrap_or_default(),
            transform: self.transform.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "transform",
                    "transform was not specified but it is required when building IcebergSortField",
                )
            })?,
            direction: self.direction.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "direction",
                    "direction was not specified but it is required when building IcebergSortField",
                )
            })?,
            null_order: self.null_order.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "null_order",
                    "null_order was not specified but it is required when building IcebergSortField",
                )
            })?,
        })
    }
}
