// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies that Shield Advanced should configure its WAF rules with the WAF <code>Block</code> action.</p>
/// <p>This is only used in the context of the <code>ResponseAction</code> setting.</p>
/// <p>JSON specification: <code>"Block": {}</code></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BlockAction {}
impl BlockAction {
    /// Creates a new builder-style object to manufacture [`BlockAction`](crate::types::BlockAction).
    pub fn builder() -> crate::types::builders::BlockActionBuilder {
        crate::types::builders::BlockActionBuilder::default()
    }
}

/// A builder for [`BlockAction`](crate::types::BlockAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BlockActionBuilder {}
impl BlockActionBuilder {
    /// Consumes the builder and constructs a [`BlockAction`](crate::types::BlockAction).
    pub fn build(self) -> crate::types::BlockAction {
        crate::types::BlockAction {}
    }
}
