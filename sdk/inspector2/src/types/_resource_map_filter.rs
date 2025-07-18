// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A resource map filter for a software bill of material report.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourceMapFilter {
    /// <p>The filter's comparison.</p>
    pub comparison: crate::types::ResourceMapComparison,
    /// <p>The filter's key.</p>
    pub key: ::std::string::String,
    /// <p>The filter's value.</p>
    pub value: ::std::option::Option<::std::string::String>,
}
impl ResourceMapFilter {
    /// <p>The filter's comparison.</p>
    pub fn comparison(&self) -> &crate::types::ResourceMapComparison {
        &self.comparison
    }
    /// <p>The filter's key.</p>
    pub fn key(&self) -> &str {
        use std::ops::Deref;
        self.key.deref()
    }
    /// <p>The filter's value.</p>
    pub fn value(&self) -> ::std::option::Option<&str> {
        self.value.as_deref()
    }
}
impl ResourceMapFilter {
    /// Creates a new builder-style object to manufacture [`ResourceMapFilter`](crate::types::ResourceMapFilter).
    pub fn builder() -> crate::types::builders::ResourceMapFilterBuilder {
        crate::types::builders::ResourceMapFilterBuilder::default()
    }
}

/// A builder for [`ResourceMapFilter`](crate::types::ResourceMapFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourceMapFilterBuilder {
    pub(crate) comparison: ::std::option::Option<crate::types::ResourceMapComparison>,
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl ResourceMapFilterBuilder {
    /// <p>The filter's comparison.</p>
    /// This field is required.
    pub fn comparison(mut self, input: crate::types::ResourceMapComparison) -> Self {
        self.comparison = ::std::option::Option::Some(input);
        self
    }
    /// <p>The filter's comparison.</p>
    pub fn set_comparison(mut self, input: ::std::option::Option<crate::types::ResourceMapComparison>) -> Self {
        self.comparison = input;
        self
    }
    /// <p>The filter's comparison.</p>
    pub fn get_comparison(&self) -> &::std::option::Option<crate::types::ResourceMapComparison> {
        &self.comparison
    }
    /// <p>The filter's key.</p>
    /// This field is required.
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The filter's key.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>The filter's key.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// <p>The filter's value.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The filter's value.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The filter's value.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`ResourceMapFilter`](crate::types::ResourceMapFilter).
    /// This method will fail if any of the following fields are not set:
    /// - [`comparison`](crate::types::builders::ResourceMapFilterBuilder::comparison)
    /// - [`key`](crate::types::builders::ResourceMapFilterBuilder::key)
    pub fn build(self) -> ::std::result::Result<crate::types::ResourceMapFilter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ResourceMapFilter {
            comparison: self.comparison.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "comparison",
                    "comparison was not specified but it is required when building ResourceMapFilter",
                )
            })?,
            key: self.key.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "key",
                    "key was not specified but it is required when building ResourceMapFilter",
                )
            })?,
            value: self.value,
        })
    }
}
