// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A transform operation that projects columns. Operations that come after a projection can only refer to projected columns.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProjectOperation {
    /// <p>Projected columns.</p>
    pub projected_columns: ::std::vec::Vec<::std::string::String>,
}
impl ProjectOperation {
    /// <p>Projected columns.</p>
    pub fn projected_columns(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.projected_columns.deref()
    }
}
impl ProjectOperation {
    /// Creates a new builder-style object to manufacture [`ProjectOperation`](crate::types::ProjectOperation).
    pub fn builder() -> crate::types::builders::ProjectOperationBuilder {
        crate::types::builders::ProjectOperationBuilder::default()
    }
}

/// A builder for [`ProjectOperation`](crate::types::ProjectOperation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProjectOperationBuilder {
    pub(crate) projected_columns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ProjectOperationBuilder {
    /// Appends an item to `projected_columns`.
    ///
    /// To override the contents of this collection use [`set_projected_columns`](Self::set_projected_columns).
    ///
    /// <p>Projected columns.</p>
    pub fn projected_columns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.projected_columns.unwrap_or_default();
        v.push(input.into());
        self.projected_columns = ::std::option::Option::Some(v);
        self
    }
    /// <p>Projected columns.</p>
    pub fn set_projected_columns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.projected_columns = input;
        self
    }
    /// <p>Projected columns.</p>
    pub fn get_projected_columns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.projected_columns
    }
    /// Consumes the builder and constructs a [`ProjectOperation`](crate::types::ProjectOperation).
    /// This method will fail if any of the following fields are not set:
    /// - [`projected_columns`](crate::types::builders::ProjectOperationBuilder::projected_columns)
    pub fn build(self) -> ::std::result::Result<crate::types::ProjectOperation, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ProjectOperation {
            projected_columns: self.projected_columns.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "projected_columns",
                    "projected_columns was not specified but it is required when building ProjectOperation",
                )
            })?,
        })
    }
}
