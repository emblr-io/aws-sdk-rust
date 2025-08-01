// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about a flow that's missing a required <code>LoopInput</code> node in a DoWhile loop.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MissingLoopInputNodeFlowValidationDetails {
    /// <p>The DoWhile loop in a flow that's missing a required <code>LoopInput</code> node.</p>
    pub loop_node: ::std::string::String,
}
impl MissingLoopInputNodeFlowValidationDetails {
    /// <p>The DoWhile loop in a flow that's missing a required <code>LoopInput</code> node.</p>
    pub fn loop_node(&self) -> &str {
        use std::ops::Deref;
        self.loop_node.deref()
    }
}
impl MissingLoopInputNodeFlowValidationDetails {
    /// Creates a new builder-style object to manufacture [`MissingLoopInputNodeFlowValidationDetails`](crate::types::MissingLoopInputNodeFlowValidationDetails).
    pub fn builder() -> crate::types::builders::MissingLoopInputNodeFlowValidationDetailsBuilder {
        crate::types::builders::MissingLoopInputNodeFlowValidationDetailsBuilder::default()
    }
}

/// A builder for [`MissingLoopInputNodeFlowValidationDetails`](crate::types::MissingLoopInputNodeFlowValidationDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MissingLoopInputNodeFlowValidationDetailsBuilder {
    pub(crate) loop_node: ::std::option::Option<::std::string::String>,
}
impl MissingLoopInputNodeFlowValidationDetailsBuilder {
    /// <p>The DoWhile loop in a flow that's missing a required <code>LoopInput</code> node.</p>
    /// This field is required.
    pub fn loop_node(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.loop_node = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The DoWhile loop in a flow that's missing a required <code>LoopInput</code> node.</p>
    pub fn set_loop_node(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.loop_node = input;
        self
    }
    /// <p>The DoWhile loop in a flow that's missing a required <code>LoopInput</code> node.</p>
    pub fn get_loop_node(&self) -> &::std::option::Option<::std::string::String> {
        &self.loop_node
    }
    /// Consumes the builder and constructs a [`MissingLoopInputNodeFlowValidationDetails`](crate::types::MissingLoopInputNodeFlowValidationDetails).
    /// This method will fail if any of the following fields are not set:
    /// - [`loop_node`](crate::types::builders::MissingLoopInputNodeFlowValidationDetailsBuilder::loop_node)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::MissingLoopInputNodeFlowValidationDetails, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::MissingLoopInputNodeFlowValidationDetails {
            loop_node: self.loop_node.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "loop_node",
                    "loop_node was not specified but it is required when building MissingLoopInputNodeFlowValidationDetails",
                )
            })?,
        })
    }
}
