// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Sort search results.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Sort {
    /// <p>The sort order for search criteria.</p>
    pub sort_order: crate::types::SortOrder,
    /// <p>The sort field for search criteria.</p>
    pub sort_field: crate::types::SortField,
}
impl Sort {
    /// <p>The sort order for search criteria.</p>
    pub fn sort_order(&self) -> &crate::types::SortOrder {
        &self.sort_order
    }
    /// <p>The sort field for search criteria.</p>
    pub fn sort_field(&self) -> &crate::types::SortField {
        &self.sort_field
    }
}
impl Sort {
    /// Creates a new builder-style object to manufacture [`Sort`](crate::types::Sort).
    pub fn builder() -> crate::types::builders::SortBuilder {
        crate::types::builders::SortBuilder::default()
    }
}

/// A builder for [`Sort`](crate::types::Sort).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SortBuilder {
    pub(crate) sort_order: ::std::option::Option<crate::types::SortOrder>,
    pub(crate) sort_field: ::std::option::Option<crate::types::SortField>,
}
impl SortBuilder {
    /// <p>The sort order for search criteria.</p>
    /// This field is required.
    pub fn sort_order(mut self, input: crate::types::SortOrder) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sort order for search criteria.</p>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::SortOrder>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>The sort order for search criteria.</p>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::SortOrder> {
        &self.sort_order
    }
    /// <p>The sort field for search criteria.</p>
    /// This field is required.
    pub fn sort_field(mut self, input: crate::types::SortField) -> Self {
        self.sort_field = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sort field for search criteria.</p>
    pub fn set_sort_field(mut self, input: ::std::option::Option<crate::types::SortField>) -> Self {
        self.sort_field = input;
        self
    }
    /// <p>The sort field for search criteria.</p>
    pub fn get_sort_field(&self) -> &::std::option::Option<crate::types::SortField> {
        &self.sort_field
    }
    /// Consumes the builder and constructs a [`Sort`](crate::types::Sort).
    /// This method will fail if any of the following fields are not set:
    /// - [`sort_order`](crate::types::builders::SortBuilder::sort_order)
    /// - [`sort_field`](crate::types::builders::SortBuilder::sort_field)
    pub fn build(self) -> ::std::result::Result<crate::types::Sort, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Sort {
            sort_order: self.sort_order.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "sort_order",
                    "sort_order was not specified but it is required when building Sort",
                )
            })?,
            sort_field: self.sort_field.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "sort_field",
                    "sort_field was not specified but it is required when building Sort",
                )
            })?,
        })
    }
}
