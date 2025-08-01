// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The model must request at least one tool (no text is generated). For example, <code>{"any" : {}}</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AnyToolChoice {}
impl AnyToolChoice {
    /// Creates a new builder-style object to manufacture [`AnyToolChoice`](crate::types::AnyToolChoice).
    pub fn builder() -> crate::types::builders::AnyToolChoiceBuilder {
        crate::types::builders::AnyToolChoiceBuilder::default()
    }
}

/// A builder for [`AnyToolChoice`](crate::types::AnyToolChoice).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AnyToolChoiceBuilder {}
impl AnyToolChoiceBuilder {
    /// Consumes the builder and constructs a [`AnyToolChoice`](crate::types::AnyToolChoice).
    pub fn build(self) -> crate::types::AnyToolChoice {
        crate::types::AnyToolChoice {}
    }
}
