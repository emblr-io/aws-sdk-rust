// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies that a value is not equal to the expression.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NotEqualToExpression {
    /// <p>The name of the column.</p>
    pub column_name: ::std::string::String,
    /// <p>The value that might not be equal to the expression.</p>
    pub value: ::std::string::String,
}
impl NotEqualToExpression {
    /// <p>The name of the column.</p>
    pub fn column_name(&self) -> &str {
        use std::ops::Deref;
        self.column_name.deref()
    }
    /// <p>The value that might not be equal to the expression.</p>
    pub fn value(&self) -> &str {
        use std::ops::Deref;
        self.value.deref()
    }
}
impl NotEqualToExpression {
    /// Creates a new builder-style object to manufacture [`NotEqualToExpression`](crate::types::NotEqualToExpression).
    pub fn builder() -> crate::types::builders::NotEqualToExpressionBuilder {
        crate::types::builders::NotEqualToExpressionBuilder::default()
    }
}

/// A builder for [`NotEqualToExpression`](crate::types::NotEqualToExpression).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NotEqualToExpressionBuilder {
    pub(crate) column_name: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl NotEqualToExpressionBuilder {
    /// <p>The name of the column.</p>
    /// This field is required.
    pub fn column_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.column_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the column.</p>
    pub fn set_column_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.column_name = input;
        self
    }
    /// <p>The name of the column.</p>
    pub fn get_column_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.column_name
    }
    /// <p>The value that might not be equal to the expression.</p>
    /// This field is required.
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value that might not be equal to the expression.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value that might not be equal to the expression.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`NotEqualToExpression`](crate::types::NotEqualToExpression).
    /// This method will fail if any of the following fields are not set:
    /// - [`column_name`](crate::types::builders::NotEqualToExpressionBuilder::column_name)
    /// - [`value`](crate::types::builders::NotEqualToExpressionBuilder::value)
    pub fn build(self) -> ::std::result::Result<crate::types::NotEqualToExpression, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::NotEqualToExpression {
            column_name: self.column_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "column_name",
                    "column_name was not specified but it is required when building NotEqualToExpression",
                )
            })?,
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building NotEqualToExpression",
                )
            })?,
        })
    }
}
