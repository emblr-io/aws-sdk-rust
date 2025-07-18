// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a structure for defining parameter conditions. Supported conditions are described here: <a href="https://docs.aws.amazon.com/databrew/latest/dg/datasets.multiple-files.html#conditions.for.dynamic.datasets">Supported conditions for dynamic datasets</a> in the <i>Glue DataBrew Developer Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FilterExpression {
    /// <p>The expression which includes condition names followed by substitution variables, possibly grouped and combined with other conditions. For example, "(starts_with :prefix1 or starts_with :prefix2) and (ends_with :suffix1 or ends_with :suffix2)". Substitution variables should start with ':' symbol.</p>
    pub expression: ::std::string::String,
    /// <p>The map of substitution variable names to their values used in this filter expression.</p>
    pub values_map: ::std::collections::HashMap<::std::string::String, ::std::string::String>,
}
impl FilterExpression {
    /// <p>The expression which includes condition names followed by substitution variables, possibly grouped and combined with other conditions. For example, "(starts_with :prefix1 or starts_with :prefix2) and (ends_with :suffix1 or ends_with :suffix2)". Substitution variables should start with ':' symbol.</p>
    pub fn expression(&self) -> &str {
        use std::ops::Deref;
        self.expression.deref()
    }
    /// <p>The map of substitution variable names to their values used in this filter expression.</p>
    pub fn values_map(&self) -> &::std::collections::HashMap<::std::string::String, ::std::string::String> {
        &self.values_map
    }
}
impl FilterExpression {
    /// Creates a new builder-style object to manufacture [`FilterExpression`](crate::types::FilterExpression).
    pub fn builder() -> crate::types::builders::FilterExpressionBuilder {
        crate::types::builders::FilterExpressionBuilder::default()
    }
}

/// A builder for [`FilterExpression`](crate::types::FilterExpression).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FilterExpressionBuilder {
    pub(crate) expression: ::std::option::Option<::std::string::String>,
    pub(crate) values_map: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl FilterExpressionBuilder {
    /// <p>The expression which includes condition names followed by substitution variables, possibly grouped and combined with other conditions. For example, "(starts_with :prefix1 or starts_with :prefix2) and (ends_with :suffix1 or ends_with :suffix2)". Substitution variables should start with ':' symbol.</p>
    /// This field is required.
    pub fn expression(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expression = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The expression which includes condition names followed by substitution variables, possibly grouped and combined with other conditions. For example, "(starts_with :prefix1 or starts_with :prefix2) and (ends_with :suffix1 or ends_with :suffix2)". Substitution variables should start with ':' symbol.</p>
    pub fn set_expression(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expression = input;
        self
    }
    /// <p>The expression which includes condition names followed by substitution variables, possibly grouped and combined with other conditions. For example, "(starts_with :prefix1 or starts_with :prefix2) and (ends_with :suffix1 or ends_with :suffix2)". Substitution variables should start with ':' symbol.</p>
    pub fn get_expression(&self) -> &::std::option::Option<::std::string::String> {
        &self.expression
    }
    /// Adds a key-value pair to `values_map`.
    ///
    /// To override the contents of this collection use [`set_values_map`](Self::set_values_map).
    ///
    /// <p>The map of substitution variable names to their values used in this filter expression.</p>
    pub fn values_map(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.values_map.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.values_map = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The map of substitution variable names to their values used in this filter expression.</p>
    pub fn set_values_map(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.values_map = input;
        self
    }
    /// <p>The map of substitution variable names to their values used in this filter expression.</p>
    pub fn get_values_map(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.values_map
    }
    /// Consumes the builder and constructs a [`FilterExpression`](crate::types::FilterExpression).
    /// This method will fail if any of the following fields are not set:
    /// - [`expression`](crate::types::builders::FilterExpressionBuilder::expression)
    /// - [`values_map`](crate::types::builders::FilterExpressionBuilder::values_map)
    pub fn build(self) -> ::std::result::Result<crate::types::FilterExpression, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FilterExpression {
            expression: self.expression.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "expression",
                    "expression was not specified but it is required when building FilterExpression",
                )
            })?,
            values_map: self.values_map.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "values_map",
                    "values_map was not specified but it is required when building FilterExpression",
                )
            })?,
        })
    }
}
