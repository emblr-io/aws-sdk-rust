// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A string for filtering Detective investigations.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StringFilter {
    /// <p>The string filter value.</p>
    pub value: ::std::string::String,
}
impl StringFilter {
    /// <p>The string filter value.</p>
    pub fn value(&self) -> &str {
        use std::ops::Deref;
        self.value.deref()
    }
}
impl StringFilter {
    /// Creates a new builder-style object to manufacture [`StringFilter`](crate::types::StringFilter).
    pub fn builder() -> crate::types::builders::StringFilterBuilder {
        crate::types::builders::StringFilterBuilder::default()
    }
}

/// A builder for [`StringFilter`](crate::types::StringFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StringFilterBuilder {
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl StringFilterBuilder {
    /// <p>The string filter value.</p>
    /// This field is required.
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string filter value.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The string filter value.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`StringFilter`](crate::types::StringFilter).
    /// This method will fail if any of the following fields are not set:
    /// - [`value`](crate::types::builders::StringFilterBuilder::value)
    pub fn build(self) -> ::std::result::Result<crate::types::StringFilter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::StringFilter {
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building StringFilter",
                )
            })?,
        })
    }
}
