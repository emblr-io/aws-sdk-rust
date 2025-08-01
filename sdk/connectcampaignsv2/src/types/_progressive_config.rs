// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Progressive config
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProgressiveConfig {
    /// The bandwidth allocation of a queue resource.
    pub bandwidth_allocation: f64,
}
impl ProgressiveConfig {
    /// The bandwidth allocation of a queue resource.
    pub fn bandwidth_allocation(&self) -> f64 {
        self.bandwidth_allocation
    }
}
impl ProgressiveConfig {
    /// Creates a new builder-style object to manufacture [`ProgressiveConfig`](crate::types::ProgressiveConfig).
    pub fn builder() -> crate::types::builders::ProgressiveConfigBuilder {
        crate::types::builders::ProgressiveConfigBuilder::default()
    }
}

/// A builder for [`ProgressiveConfig`](crate::types::ProgressiveConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProgressiveConfigBuilder {
    pub(crate) bandwidth_allocation: ::std::option::Option<f64>,
}
impl ProgressiveConfigBuilder {
    /// The bandwidth allocation of a queue resource.
    /// This field is required.
    pub fn bandwidth_allocation(mut self, input: f64) -> Self {
        self.bandwidth_allocation = ::std::option::Option::Some(input);
        self
    }
    /// The bandwidth allocation of a queue resource.
    pub fn set_bandwidth_allocation(mut self, input: ::std::option::Option<f64>) -> Self {
        self.bandwidth_allocation = input;
        self
    }
    /// The bandwidth allocation of a queue resource.
    pub fn get_bandwidth_allocation(&self) -> &::std::option::Option<f64> {
        &self.bandwidth_allocation
    }
    /// Consumes the builder and constructs a [`ProgressiveConfig`](crate::types::ProgressiveConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`bandwidth_allocation`](crate::types::builders::ProgressiveConfigBuilder::bandwidth_allocation)
    pub fn build(self) -> ::std::result::Result<crate::types::ProgressiveConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ProgressiveConfig {
            bandwidth_allocation: self.bandwidth_allocation.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "bandwidth_allocation",
                    "bandwidth_allocation was not specified but it is required when building ProgressiveConfig",
                )
            })?,
        })
    }
}
