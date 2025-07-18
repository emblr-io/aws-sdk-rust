// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The input structure for specifying Platform. Platform refers to the unique name of the specific platform the instrument is attached to. For satellites it is the name of the satellite, eg. landsat-8 (Landsat-8), sentinel-2a.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PlatformInput {
    /// <p>The value of the platform.</p>
    pub value: ::std::string::String,
    /// <p>The ComparisonOperator to use with PlatformInput.</p>
    pub comparison_operator: ::std::option::Option<crate::types::ComparisonOperator>,
}
impl PlatformInput {
    /// <p>The value of the platform.</p>
    pub fn value(&self) -> &str {
        use std::ops::Deref;
        self.value.deref()
    }
    /// <p>The ComparisonOperator to use with PlatformInput.</p>
    pub fn comparison_operator(&self) -> ::std::option::Option<&crate::types::ComparisonOperator> {
        self.comparison_operator.as_ref()
    }
}
impl PlatformInput {
    /// Creates a new builder-style object to manufacture [`PlatformInput`](crate::types::PlatformInput).
    pub fn builder() -> crate::types::builders::PlatformInputBuilder {
        crate::types::builders::PlatformInputBuilder::default()
    }
}

/// A builder for [`PlatformInput`](crate::types::PlatformInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PlatformInputBuilder {
    pub(crate) value: ::std::option::Option<::std::string::String>,
    pub(crate) comparison_operator: ::std::option::Option<crate::types::ComparisonOperator>,
}
impl PlatformInputBuilder {
    /// <p>The value of the platform.</p>
    /// This field is required.
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the platform.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value of the platform.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// <p>The ComparisonOperator to use with PlatformInput.</p>
    pub fn comparison_operator(mut self, input: crate::types::ComparisonOperator) -> Self {
        self.comparison_operator = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ComparisonOperator to use with PlatformInput.</p>
    pub fn set_comparison_operator(mut self, input: ::std::option::Option<crate::types::ComparisonOperator>) -> Self {
        self.comparison_operator = input;
        self
    }
    /// <p>The ComparisonOperator to use with PlatformInput.</p>
    pub fn get_comparison_operator(&self) -> &::std::option::Option<crate::types::ComparisonOperator> {
        &self.comparison_operator
    }
    /// Consumes the builder and constructs a [`PlatformInput`](crate::types::PlatformInput).
    /// This method will fail if any of the following fields are not set:
    /// - [`value`](crate::types::builders::PlatformInputBuilder::value)
    pub fn build(self) -> ::std::result::Result<crate::types::PlatformInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PlatformInput {
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building PlatformInput",
                )
            })?,
            comparison_operator: self.comparison_operator,
        })
    }
}
