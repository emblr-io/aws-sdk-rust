// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies that WAF should do nothing. This is used for the <code>OverrideAction</code> setting on a <code>Rule</code> when the rule uses a rule group reference statement.</p>
/// <p>This is used in the context of other settings, for example to specify values for <code>RuleAction</code> and web ACL <code>DefaultAction</code>.</p>
/// <p>JSON specification: <code>"None": {}</code></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NoneAction {}
impl NoneAction {
    /// Creates a new builder-style object to manufacture [`NoneAction`](crate::types::NoneAction).
    pub fn builder() -> crate::types::builders::NoneActionBuilder {
        crate::types::builders::NoneActionBuilder::default()
    }
}

/// A builder for [`NoneAction`](crate::types::NoneAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NoneActionBuilder {}
impl NoneActionBuilder {
    /// Consumes the builder and constructs a [`NoneAction`](crate::types::NoneAction).
    pub fn build(self) -> crate::types::NoneAction {
        crate::types::NoneAction {}
    }
}
