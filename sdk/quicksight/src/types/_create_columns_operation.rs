// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A transform operation that creates calculated columns. Columns created in one such operation form a lexical closure.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateColumnsOperation {
    /// <p>Calculated columns to create.</p>
    pub columns: ::std::vec::Vec<crate::types::CalculatedColumn>,
}
impl CreateColumnsOperation {
    /// <p>Calculated columns to create.</p>
    pub fn columns(&self) -> &[crate::types::CalculatedColumn] {
        use std::ops::Deref;
        self.columns.deref()
    }
}
impl CreateColumnsOperation {
    /// Creates a new builder-style object to manufacture [`CreateColumnsOperation`](crate::types::CreateColumnsOperation).
    pub fn builder() -> crate::types::builders::CreateColumnsOperationBuilder {
        crate::types::builders::CreateColumnsOperationBuilder::default()
    }
}

/// A builder for [`CreateColumnsOperation`](crate::types::CreateColumnsOperation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateColumnsOperationBuilder {
    pub(crate) columns: ::std::option::Option<::std::vec::Vec<crate::types::CalculatedColumn>>,
}
impl CreateColumnsOperationBuilder {
    /// Appends an item to `columns`.
    ///
    /// To override the contents of this collection use [`set_columns`](Self::set_columns).
    ///
    /// <p>Calculated columns to create.</p>
    pub fn columns(mut self, input: crate::types::CalculatedColumn) -> Self {
        let mut v = self.columns.unwrap_or_default();
        v.push(input);
        self.columns = ::std::option::Option::Some(v);
        self
    }
    /// <p>Calculated columns to create.</p>
    pub fn set_columns(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CalculatedColumn>>) -> Self {
        self.columns = input;
        self
    }
    /// <p>Calculated columns to create.</p>
    pub fn get_columns(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CalculatedColumn>> {
        &self.columns
    }
    /// Consumes the builder and constructs a [`CreateColumnsOperation`](crate::types::CreateColumnsOperation).
    /// This method will fail if any of the following fields are not set:
    /// - [`columns`](crate::types::builders::CreateColumnsOperationBuilder::columns)
    pub fn build(self) -> ::std::result::Result<crate::types::CreateColumnsOperation, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CreateColumnsOperation {
            columns: self.columns.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "columns",
                    "columns was not specified but it is required when building CreateColumnsOperation",
                )
            })?,
        })
    }
}
