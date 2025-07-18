// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines a prepaid payment model that allows buyers to configure the entitlements they want to purchase and the duration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConfigurableUpfrontPricingTermConfiguration {
    /// <p>Defines the length of time for which the particular pricing/dimension is being purchased by the acceptor.</p>
    pub selector_value: ::std::string::String,
    /// <p>Defines the dimensions that the acceptor has purchased from the overall set of dimensions presented in the rate card.</p>
    pub dimensions: ::std::vec::Vec<crate::types::Dimension>,
}
impl ConfigurableUpfrontPricingTermConfiguration {
    /// <p>Defines the length of time for which the particular pricing/dimension is being purchased by the acceptor.</p>
    pub fn selector_value(&self) -> &str {
        use std::ops::Deref;
        self.selector_value.deref()
    }
    /// <p>Defines the dimensions that the acceptor has purchased from the overall set of dimensions presented in the rate card.</p>
    pub fn dimensions(&self) -> &[crate::types::Dimension] {
        use std::ops::Deref;
        self.dimensions.deref()
    }
}
impl ConfigurableUpfrontPricingTermConfiguration {
    /// Creates a new builder-style object to manufacture [`ConfigurableUpfrontPricingTermConfiguration`](crate::types::ConfigurableUpfrontPricingTermConfiguration).
    pub fn builder() -> crate::types::builders::ConfigurableUpfrontPricingTermConfigurationBuilder {
        crate::types::builders::ConfigurableUpfrontPricingTermConfigurationBuilder::default()
    }
}

/// A builder for [`ConfigurableUpfrontPricingTermConfiguration`](crate::types::ConfigurableUpfrontPricingTermConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConfigurableUpfrontPricingTermConfigurationBuilder {
    pub(crate) selector_value: ::std::option::Option<::std::string::String>,
    pub(crate) dimensions: ::std::option::Option<::std::vec::Vec<crate::types::Dimension>>,
}
impl ConfigurableUpfrontPricingTermConfigurationBuilder {
    /// <p>Defines the length of time for which the particular pricing/dimension is being purchased by the acceptor.</p>
    /// This field is required.
    pub fn selector_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.selector_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Defines the length of time for which the particular pricing/dimension is being purchased by the acceptor.</p>
    pub fn set_selector_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.selector_value = input;
        self
    }
    /// <p>Defines the length of time for which the particular pricing/dimension is being purchased by the acceptor.</p>
    pub fn get_selector_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.selector_value
    }
    /// Appends an item to `dimensions`.
    ///
    /// To override the contents of this collection use [`set_dimensions`](Self::set_dimensions).
    ///
    /// <p>Defines the dimensions that the acceptor has purchased from the overall set of dimensions presented in the rate card.</p>
    pub fn dimensions(mut self, input: crate::types::Dimension) -> Self {
        let mut v = self.dimensions.unwrap_or_default();
        v.push(input);
        self.dimensions = ::std::option::Option::Some(v);
        self
    }
    /// <p>Defines the dimensions that the acceptor has purchased from the overall set of dimensions presented in the rate card.</p>
    pub fn set_dimensions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Dimension>>) -> Self {
        self.dimensions = input;
        self
    }
    /// <p>Defines the dimensions that the acceptor has purchased from the overall set of dimensions presented in the rate card.</p>
    pub fn get_dimensions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Dimension>> {
        &self.dimensions
    }
    /// Consumes the builder and constructs a [`ConfigurableUpfrontPricingTermConfiguration`](crate::types::ConfigurableUpfrontPricingTermConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`selector_value`](crate::types::builders::ConfigurableUpfrontPricingTermConfigurationBuilder::selector_value)
    /// - [`dimensions`](crate::types::builders::ConfigurableUpfrontPricingTermConfigurationBuilder::dimensions)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::ConfigurableUpfrontPricingTermConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ConfigurableUpfrontPricingTermConfiguration {
            selector_value: self.selector_value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "selector_value",
                    "selector_value was not specified but it is required when building ConfigurableUpfrontPricingTermConfiguration",
                )
            })?,
            dimensions: self.dimensions.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "dimensions",
                    "dimensions was not specified but it is required when building ConfigurableUpfrontPricingTermConfiguration",
                )
            })?,
        })
    }
}
