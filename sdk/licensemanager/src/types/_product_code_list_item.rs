// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list item that contains a product code.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProductCodeListItem {
    /// <p>The product code ID</p>
    pub product_code_id: ::std::string::String,
    /// <p>The product code type</p>
    pub product_code_type: crate::types::ProductCodeType,
}
impl ProductCodeListItem {
    /// <p>The product code ID</p>
    pub fn product_code_id(&self) -> &str {
        use std::ops::Deref;
        self.product_code_id.deref()
    }
    /// <p>The product code type</p>
    pub fn product_code_type(&self) -> &crate::types::ProductCodeType {
        &self.product_code_type
    }
}
impl ProductCodeListItem {
    /// Creates a new builder-style object to manufacture [`ProductCodeListItem`](crate::types::ProductCodeListItem).
    pub fn builder() -> crate::types::builders::ProductCodeListItemBuilder {
        crate::types::builders::ProductCodeListItemBuilder::default()
    }
}

/// A builder for [`ProductCodeListItem`](crate::types::ProductCodeListItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProductCodeListItemBuilder {
    pub(crate) product_code_id: ::std::option::Option<::std::string::String>,
    pub(crate) product_code_type: ::std::option::Option<crate::types::ProductCodeType>,
}
impl ProductCodeListItemBuilder {
    /// <p>The product code ID</p>
    /// This field is required.
    pub fn product_code_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.product_code_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The product code ID</p>
    pub fn set_product_code_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.product_code_id = input;
        self
    }
    /// <p>The product code ID</p>
    pub fn get_product_code_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.product_code_id
    }
    /// <p>The product code type</p>
    /// This field is required.
    pub fn product_code_type(mut self, input: crate::types::ProductCodeType) -> Self {
        self.product_code_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The product code type</p>
    pub fn set_product_code_type(mut self, input: ::std::option::Option<crate::types::ProductCodeType>) -> Self {
        self.product_code_type = input;
        self
    }
    /// <p>The product code type</p>
    pub fn get_product_code_type(&self) -> &::std::option::Option<crate::types::ProductCodeType> {
        &self.product_code_type
    }
    /// Consumes the builder and constructs a [`ProductCodeListItem`](crate::types::ProductCodeListItem).
    /// This method will fail if any of the following fields are not set:
    /// - [`product_code_id`](crate::types::builders::ProductCodeListItemBuilder::product_code_id)
    /// - [`product_code_type`](crate::types::builders::ProductCodeListItemBuilder::product_code_type)
    pub fn build(self) -> ::std::result::Result<crate::types::ProductCodeListItem, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ProductCodeListItem {
            product_code_id: self.product_code_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "product_code_id",
                    "product_code_id was not specified but it is required when building ProductCodeListItem",
                )
            })?,
            product_code_type: self.product_code_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "product_code_type",
                    "product_code_type was not specified but it is required when building ProductCodeListItem",
                )
            })?,
        })
    }
}
