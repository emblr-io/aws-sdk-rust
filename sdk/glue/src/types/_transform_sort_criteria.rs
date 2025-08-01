// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The sorting criteria that are associated with the machine learning transform.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TransformSortCriteria {
    /// <p>The column to be used in the sorting criteria that are associated with the machine learning transform.</p>
    pub column: crate::types::TransformSortColumnType,
    /// <p>The sort direction to be used in the sorting criteria that are associated with the machine learning transform.</p>
    pub sort_direction: crate::types::SortDirectionType,
}
impl TransformSortCriteria {
    /// <p>The column to be used in the sorting criteria that are associated with the machine learning transform.</p>
    pub fn column(&self) -> &crate::types::TransformSortColumnType {
        &self.column
    }
    /// <p>The sort direction to be used in the sorting criteria that are associated with the machine learning transform.</p>
    pub fn sort_direction(&self) -> &crate::types::SortDirectionType {
        &self.sort_direction
    }
}
impl TransformSortCriteria {
    /// Creates a new builder-style object to manufacture [`TransformSortCriteria`](crate::types::TransformSortCriteria).
    pub fn builder() -> crate::types::builders::TransformSortCriteriaBuilder {
        crate::types::builders::TransformSortCriteriaBuilder::default()
    }
}

/// A builder for [`TransformSortCriteria`](crate::types::TransformSortCriteria).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TransformSortCriteriaBuilder {
    pub(crate) column: ::std::option::Option<crate::types::TransformSortColumnType>,
    pub(crate) sort_direction: ::std::option::Option<crate::types::SortDirectionType>,
}
impl TransformSortCriteriaBuilder {
    /// <p>The column to be used in the sorting criteria that are associated with the machine learning transform.</p>
    /// This field is required.
    pub fn column(mut self, input: crate::types::TransformSortColumnType) -> Self {
        self.column = ::std::option::Option::Some(input);
        self
    }
    /// <p>The column to be used in the sorting criteria that are associated with the machine learning transform.</p>
    pub fn set_column(mut self, input: ::std::option::Option<crate::types::TransformSortColumnType>) -> Self {
        self.column = input;
        self
    }
    /// <p>The column to be used in the sorting criteria that are associated with the machine learning transform.</p>
    pub fn get_column(&self) -> &::std::option::Option<crate::types::TransformSortColumnType> {
        &self.column
    }
    /// <p>The sort direction to be used in the sorting criteria that are associated with the machine learning transform.</p>
    /// This field is required.
    pub fn sort_direction(mut self, input: crate::types::SortDirectionType) -> Self {
        self.sort_direction = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sort direction to be used in the sorting criteria that are associated with the machine learning transform.</p>
    pub fn set_sort_direction(mut self, input: ::std::option::Option<crate::types::SortDirectionType>) -> Self {
        self.sort_direction = input;
        self
    }
    /// <p>The sort direction to be used in the sorting criteria that are associated with the machine learning transform.</p>
    pub fn get_sort_direction(&self) -> &::std::option::Option<crate::types::SortDirectionType> {
        &self.sort_direction
    }
    /// Consumes the builder and constructs a [`TransformSortCriteria`](crate::types::TransformSortCriteria).
    /// This method will fail if any of the following fields are not set:
    /// - [`column`](crate::types::builders::TransformSortCriteriaBuilder::column)
    /// - [`sort_direction`](crate::types::builders::TransformSortCriteriaBuilder::sort_direction)
    pub fn build(self) -> ::std::result::Result<crate::types::TransformSortCriteria, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TransformSortCriteria {
            column: self.column.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "column",
                    "column was not specified but it is required when building TransformSortCriteria",
                )
            })?,
            sort_direction: self.sort_direction.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "sort_direction",
                    "sort_direction was not specified but it is required when building TransformSortCriteria",
                )
            })?,
        })
    }
}
