// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines the dimensions that the acceptor has purchased from the overall set of dimensions presented in the rate card.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Dimension {
    /// <p>The name of key value of the dimension.</p>
    pub dimension_key: ::std::string::String,
    /// <p>The number of units of the dimension the acceptor has purchased.</p><note>
    /// <p>For Agreements with <code>ConfigurableUpfrontPricingTerm</code>, the <code>RateCard</code> section will define the prices and dimensions defined by the seller (proposer), whereas the <code>Configuration</code> section will define the actual dimensions, prices, and units the buyer has chosen to accept.</p>
    /// </note>
    pub dimension_value: i32,
}
impl Dimension {
    /// <p>The name of key value of the dimension.</p>
    pub fn dimension_key(&self) -> &str {
        use std::ops::Deref;
        self.dimension_key.deref()
    }
    /// <p>The number of units of the dimension the acceptor has purchased.</p><note>
    /// <p>For Agreements with <code>ConfigurableUpfrontPricingTerm</code>, the <code>RateCard</code> section will define the prices and dimensions defined by the seller (proposer), whereas the <code>Configuration</code> section will define the actual dimensions, prices, and units the buyer has chosen to accept.</p>
    /// </note>
    pub fn dimension_value(&self) -> i32 {
        self.dimension_value
    }
}
impl Dimension {
    /// Creates a new builder-style object to manufacture [`Dimension`](crate::types::Dimension).
    pub fn builder() -> crate::types::builders::DimensionBuilder {
        crate::types::builders::DimensionBuilder::default()
    }
}

/// A builder for [`Dimension`](crate::types::Dimension).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DimensionBuilder {
    pub(crate) dimension_key: ::std::option::Option<::std::string::String>,
    pub(crate) dimension_value: ::std::option::Option<i32>,
}
impl DimensionBuilder {
    /// <p>The name of key value of the dimension.</p>
    /// This field is required.
    pub fn dimension_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dimension_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of key value of the dimension.</p>
    pub fn set_dimension_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dimension_key = input;
        self
    }
    /// <p>The name of key value of the dimension.</p>
    pub fn get_dimension_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.dimension_key
    }
    /// <p>The number of units of the dimension the acceptor has purchased.</p><note>
    /// <p>For Agreements with <code>ConfigurableUpfrontPricingTerm</code>, the <code>RateCard</code> section will define the prices and dimensions defined by the seller (proposer), whereas the <code>Configuration</code> section will define the actual dimensions, prices, and units the buyer has chosen to accept.</p>
    /// </note>
    /// This field is required.
    pub fn dimension_value(mut self, input: i32) -> Self {
        self.dimension_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of units of the dimension the acceptor has purchased.</p><note>
    /// <p>For Agreements with <code>ConfigurableUpfrontPricingTerm</code>, the <code>RateCard</code> section will define the prices and dimensions defined by the seller (proposer), whereas the <code>Configuration</code> section will define the actual dimensions, prices, and units the buyer has chosen to accept.</p>
    /// </note>
    pub fn set_dimension_value(mut self, input: ::std::option::Option<i32>) -> Self {
        self.dimension_value = input;
        self
    }
    /// <p>The number of units of the dimension the acceptor has purchased.</p><note>
    /// <p>For Agreements with <code>ConfigurableUpfrontPricingTerm</code>, the <code>RateCard</code> section will define the prices and dimensions defined by the seller (proposer), whereas the <code>Configuration</code> section will define the actual dimensions, prices, and units the buyer has chosen to accept.</p>
    /// </note>
    pub fn get_dimension_value(&self) -> &::std::option::Option<i32> {
        &self.dimension_value
    }
    /// Consumes the builder and constructs a [`Dimension`](crate::types::Dimension).
    /// This method will fail if any of the following fields are not set:
    /// - [`dimension_key`](crate::types::builders::DimensionBuilder::dimension_key)
    pub fn build(self) -> ::std::result::Result<crate::types::Dimension, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Dimension {
            dimension_key: self.dimension_key.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "dimension_key",
                    "dimension_key was not specified but it is required when building Dimension",
                )
            })?,
            dimension_value: self.dimension_value.unwrap_or_default(),
        })
    }
}
