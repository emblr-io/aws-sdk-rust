// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies attributes for sorting a list of built-in slot types.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BuiltInSlotTypeSortBy {
    /// <p>The attribute to use to sort the list of built-in intents.</p>
    pub attribute: crate::types::BuiltInSlotTypeSortAttribute,
    /// <p>The order to sort the list. You can choose ascending or descending.</p>
    pub order: crate::types::SortOrder,
}
impl BuiltInSlotTypeSortBy {
    /// <p>The attribute to use to sort the list of built-in intents.</p>
    pub fn attribute(&self) -> &crate::types::BuiltInSlotTypeSortAttribute {
        &self.attribute
    }
    /// <p>The order to sort the list. You can choose ascending or descending.</p>
    pub fn order(&self) -> &crate::types::SortOrder {
        &self.order
    }
}
impl BuiltInSlotTypeSortBy {
    /// Creates a new builder-style object to manufacture [`BuiltInSlotTypeSortBy`](crate::types::BuiltInSlotTypeSortBy).
    pub fn builder() -> crate::types::builders::BuiltInSlotTypeSortByBuilder {
        crate::types::builders::BuiltInSlotTypeSortByBuilder::default()
    }
}

/// A builder for [`BuiltInSlotTypeSortBy`](crate::types::BuiltInSlotTypeSortBy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BuiltInSlotTypeSortByBuilder {
    pub(crate) attribute: ::std::option::Option<crate::types::BuiltInSlotTypeSortAttribute>,
    pub(crate) order: ::std::option::Option<crate::types::SortOrder>,
}
impl BuiltInSlotTypeSortByBuilder {
    /// <p>The attribute to use to sort the list of built-in intents.</p>
    /// This field is required.
    pub fn attribute(mut self, input: crate::types::BuiltInSlotTypeSortAttribute) -> Self {
        self.attribute = ::std::option::Option::Some(input);
        self
    }
    /// <p>The attribute to use to sort the list of built-in intents.</p>
    pub fn set_attribute(mut self, input: ::std::option::Option<crate::types::BuiltInSlotTypeSortAttribute>) -> Self {
        self.attribute = input;
        self
    }
    /// <p>The attribute to use to sort the list of built-in intents.</p>
    pub fn get_attribute(&self) -> &::std::option::Option<crate::types::BuiltInSlotTypeSortAttribute> {
        &self.attribute
    }
    /// <p>The order to sort the list. You can choose ascending or descending.</p>
    /// This field is required.
    pub fn order(mut self, input: crate::types::SortOrder) -> Self {
        self.order = ::std::option::Option::Some(input);
        self
    }
    /// <p>The order to sort the list. You can choose ascending or descending.</p>
    pub fn set_order(mut self, input: ::std::option::Option<crate::types::SortOrder>) -> Self {
        self.order = input;
        self
    }
    /// <p>The order to sort the list. You can choose ascending or descending.</p>
    pub fn get_order(&self) -> &::std::option::Option<crate::types::SortOrder> {
        &self.order
    }
    /// Consumes the builder and constructs a [`BuiltInSlotTypeSortBy`](crate::types::BuiltInSlotTypeSortBy).
    /// This method will fail if any of the following fields are not set:
    /// - [`attribute`](crate::types::builders::BuiltInSlotTypeSortByBuilder::attribute)
    /// - [`order`](crate::types::builders::BuiltInSlotTypeSortByBuilder::order)
    pub fn build(self) -> ::std::result::Result<crate::types::BuiltInSlotTypeSortBy, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::BuiltInSlotTypeSortBy {
            attribute: self.attribute.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "attribute",
                    "attribute was not specified but it is required when building BuiltInSlotTypeSortBy",
                )
            })?,
            order: self.order.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "order",
                    "order was not specified but it is required when building BuiltInSlotTypeSortBy",
                )
            })?,
        })
    }
}
