// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A transform operation that removes tags associated with a column.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UntagColumnOperation {
    /// <p>The column that this operation acts on.</p>
    pub column_name: ::std::string::String,
    /// <p>The column tags to remove from this column.</p>
    pub tag_names: ::std::vec::Vec<crate::types::ColumnTagName>,
}
impl UntagColumnOperation {
    /// <p>The column that this operation acts on.</p>
    pub fn column_name(&self) -> &str {
        use std::ops::Deref;
        self.column_name.deref()
    }
    /// <p>The column tags to remove from this column.</p>
    pub fn tag_names(&self) -> &[crate::types::ColumnTagName] {
        use std::ops::Deref;
        self.tag_names.deref()
    }
}
impl UntagColumnOperation {
    /// Creates a new builder-style object to manufacture [`UntagColumnOperation`](crate::types::UntagColumnOperation).
    pub fn builder() -> crate::types::builders::UntagColumnOperationBuilder {
        crate::types::builders::UntagColumnOperationBuilder::default()
    }
}

/// A builder for [`UntagColumnOperation`](crate::types::UntagColumnOperation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UntagColumnOperationBuilder {
    pub(crate) column_name: ::std::option::Option<::std::string::String>,
    pub(crate) tag_names: ::std::option::Option<::std::vec::Vec<crate::types::ColumnTagName>>,
}
impl UntagColumnOperationBuilder {
    /// <p>The column that this operation acts on.</p>
    /// This field is required.
    pub fn column_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.column_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The column that this operation acts on.</p>
    pub fn set_column_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.column_name = input;
        self
    }
    /// <p>The column that this operation acts on.</p>
    pub fn get_column_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.column_name
    }
    /// Appends an item to `tag_names`.
    ///
    /// To override the contents of this collection use [`set_tag_names`](Self::set_tag_names).
    ///
    /// <p>The column tags to remove from this column.</p>
    pub fn tag_names(mut self, input: crate::types::ColumnTagName) -> Self {
        let mut v = self.tag_names.unwrap_or_default();
        v.push(input);
        self.tag_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The column tags to remove from this column.</p>
    pub fn set_tag_names(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ColumnTagName>>) -> Self {
        self.tag_names = input;
        self
    }
    /// <p>The column tags to remove from this column.</p>
    pub fn get_tag_names(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ColumnTagName>> {
        &self.tag_names
    }
    /// Consumes the builder and constructs a [`UntagColumnOperation`](crate::types::UntagColumnOperation).
    /// This method will fail if any of the following fields are not set:
    /// - [`column_name`](crate::types::builders::UntagColumnOperationBuilder::column_name)
    /// - [`tag_names`](crate::types::builders::UntagColumnOperationBuilder::tag_names)
    pub fn build(self) -> ::std::result::Result<crate::types::UntagColumnOperation, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::UntagColumnOperation {
            column_name: self.column_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "column_name",
                    "column_name was not specified but it is required when building UntagColumnOperation",
                )
            })?,
            tag_names: self.tag_names.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "tag_names",
                    "tag_names was not specified but it is required when building UntagColumnOperation",
                )
            })?,
        })
    }
}
