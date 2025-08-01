// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The threshold for the calculated attribute.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Threshold {
    /// <p>The value of the threshold.</p>
    pub value: ::std::string::String,
    /// <p>The operator of the threshold.</p>
    pub operator: crate::types::Operator,
}
impl Threshold {
    /// <p>The value of the threshold.</p>
    pub fn value(&self) -> &str {
        use std::ops::Deref;
        self.value.deref()
    }
    /// <p>The operator of the threshold.</p>
    pub fn operator(&self) -> &crate::types::Operator {
        &self.operator
    }
}
impl Threshold {
    /// Creates a new builder-style object to manufacture [`Threshold`](crate::types::Threshold).
    pub fn builder() -> crate::types::builders::ThresholdBuilder {
        crate::types::builders::ThresholdBuilder::default()
    }
}

/// A builder for [`Threshold`](crate::types::Threshold).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ThresholdBuilder {
    pub(crate) value: ::std::option::Option<::std::string::String>,
    pub(crate) operator: ::std::option::Option<crate::types::Operator>,
}
impl ThresholdBuilder {
    /// <p>The value of the threshold.</p>
    /// This field is required.
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the threshold.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value of the threshold.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// <p>The operator of the threshold.</p>
    /// This field is required.
    pub fn operator(mut self, input: crate::types::Operator) -> Self {
        self.operator = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operator of the threshold.</p>
    pub fn set_operator(mut self, input: ::std::option::Option<crate::types::Operator>) -> Self {
        self.operator = input;
        self
    }
    /// <p>The operator of the threshold.</p>
    pub fn get_operator(&self) -> &::std::option::Option<crate::types::Operator> {
        &self.operator
    }
    /// Consumes the builder and constructs a [`Threshold`](crate::types::Threshold).
    /// This method will fail if any of the following fields are not set:
    /// - [`value`](crate::types::builders::ThresholdBuilder::value)
    /// - [`operator`](crate::types::builders::ThresholdBuilder::operator)
    pub fn build(self) -> ::std::result::Result<crate::types::Threshold, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Threshold {
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building Threshold",
                )
            })?,
            operator: self.operator.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "operator",
                    "operator was not specified but it is required when building Threshold",
                )
            })?,
        })
    }
}
