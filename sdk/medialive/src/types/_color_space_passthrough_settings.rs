// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Passthrough applies no color space conversion to the output
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ColorSpacePassthroughSettings {}
impl ColorSpacePassthroughSettings {
    /// Creates a new builder-style object to manufacture [`ColorSpacePassthroughSettings`](crate::types::ColorSpacePassthroughSettings).
    pub fn builder() -> crate::types::builders::ColorSpacePassthroughSettingsBuilder {
        crate::types::builders::ColorSpacePassthroughSettingsBuilder::default()
    }
}

/// A builder for [`ColorSpacePassthroughSettings`](crate::types::ColorSpacePassthroughSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ColorSpacePassthroughSettingsBuilder {}
impl ColorSpacePassthroughSettingsBuilder {
    /// Consumes the builder and constructs a [`ColorSpacePassthroughSettings`](crate::types::ColorSpacePassthroughSettings).
    pub fn build(self) -> crate::types::ColorSpacePassthroughSettings {
        crate::types::ColorSpacePassthroughSettings {}
    }
}
