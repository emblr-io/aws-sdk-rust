// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summary of an applied parameter to an <code>EnabledBaseline</code> resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EnabledBaselineParameterSummary {
    /// <p>A string denoting the parameter key.</p>
    pub key: ::std::string::String,
    /// <p>A low-level document object of any type (for example, a Java Object).</p>
    pub value: ::aws_smithy_types::Document,
}
impl EnabledBaselineParameterSummary {
    /// <p>A string denoting the parameter key.</p>
    pub fn key(&self) -> &str {
        use std::ops::Deref;
        self.key.deref()
    }
    /// <p>A low-level document object of any type (for example, a Java Object).</p>
    pub fn value(&self) -> &::aws_smithy_types::Document {
        &self.value
    }
}
impl EnabledBaselineParameterSummary {
    /// Creates a new builder-style object to manufacture [`EnabledBaselineParameterSummary`](crate::types::EnabledBaselineParameterSummary).
    pub fn builder() -> crate::types::builders::EnabledBaselineParameterSummaryBuilder {
        crate::types::builders::EnabledBaselineParameterSummaryBuilder::default()
    }
}

/// A builder for [`EnabledBaselineParameterSummary`](crate::types::EnabledBaselineParameterSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EnabledBaselineParameterSummaryBuilder {
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::aws_smithy_types::Document>,
}
impl EnabledBaselineParameterSummaryBuilder {
    /// <p>A string denoting the parameter key.</p>
    /// This field is required.
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string denoting the parameter key.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>A string denoting the parameter key.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// <p>A low-level document object of any type (for example, a Java Object).</p>
    /// This field is required.
    pub fn value(mut self, input: ::aws_smithy_types::Document) -> Self {
        self.value = ::std::option::Option::Some(input);
        self
    }
    /// <p>A low-level document object of any type (for example, a Java Object).</p>
    pub fn set_value(mut self, input: ::std::option::Option<::aws_smithy_types::Document>) -> Self {
        self.value = input;
        self
    }
    /// <p>A low-level document object of any type (for example, a Java Object).</p>
    pub fn get_value(&self) -> &::std::option::Option<::aws_smithy_types::Document> {
        &self.value
    }
    /// Consumes the builder and constructs a [`EnabledBaselineParameterSummary`](crate::types::EnabledBaselineParameterSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`key`](crate::types::builders::EnabledBaselineParameterSummaryBuilder::key)
    /// - [`value`](crate::types::builders::EnabledBaselineParameterSummaryBuilder::value)
    pub fn build(self) -> ::std::result::Result<crate::types::EnabledBaselineParameterSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::EnabledBaselineParameterSummary {
            key: self.key.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "key",
                    "key was not specified but it is required when building EnabledBaselineParameterSummary",
                )
            })?,
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building EnabledBaselineParameterSummary",
                )
            })?,
        })
    }
}
