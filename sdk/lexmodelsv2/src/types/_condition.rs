// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides an expression that evaluates to true or false.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Condition {
    /// <p>The expression string that is evaluated.</p>
    pub expression_string: ::std::string::String,
}
impl Condition {
    /// <p>The expression string that is evaluated.</p>
    pub fn expression_string(&self) -> &str {
        use std::ops::Deref;
        self.expression_string.deref()
    }
}
impl Condition {
    /// Creates a new builder-style object to manufacture [`Condition`](crate::types::Condition).
    pub fn builder() -> crate::types::builders::ConditionBuilder {
        crate::types::builders::ConditionBuilder::default()
    }
}

/// A builder for [`Condition`](crate::types::Condition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConditionBuilder {
    pub(crate) expression_string: ::std::option::Option<::std::string::String>,
}
impl ConditionBuilder {
    /// <p>The expression string that is evaluated.</p>
    /// This field is required.
    pub fn expression_string(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expression_string = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The expression string that is evaluated.</p>
    pub fn set_expression_string(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expression_string = input;
        self
    }
    /// <p>The expression string that is evaluated.</p>
    pub fn get_expression_string(&self) -> &::std::option::Option<::std::string::String> {
        &self.expression_string
    }
    /// Consumes the builder and constructs a [`Condition`](crate::types::Condition).
    /// This method will fail if any of the following fields are not set:
    /// - [`expression_string`](crate::types::builders::ConditionBuilder::expression_string)
    pub fn build(self) -> ::std::result::Result<crate::types::Condition, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Condition {
            expression_string: self.expression_string.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "expression_string",
                    "expression_string was not specified but it is required when building Condition",
                )
            })?,
        })
    }
}
