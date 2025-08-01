// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains configurations for the input node of a DoWhile loop in the flow.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LoopInputFlowNodeConfiguration {}
impl LoopInputFlowNodeConfiguration {
    /// Creates a new builder-style object to manufacture [`LoopInputFlowNodeConfiguration`](crate::types::LoopInputFlowNodeConfiguration).
    pub fn builder() -> crate::types::builders::LoopInputFlowNodeConfigurationBuilder {
        crate::types::builders::LoopInputFlowNodeConfigurationBuilder::default()
    }
}

/// A builder for [`LoopInputFlowNodeConfiguration`](crate::types::LoopInputFlowNodeConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LoopInputFlowNodeConfigurationBuilder {}
impl LoopInputFlowNodeConfigurationBuilder {
    /// Consumes the builder and constructs a [`LoopInputFlowNodeConfiguration`](crate::types::LoopInputFlowNodeConfiguration).
    pub fn build(self) -> crate::types::LoopInputFlowNodeConfiguration {
        crate::types::LoopInputFlowNodeConfiguration {}
    }
}
