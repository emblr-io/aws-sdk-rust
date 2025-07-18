// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about a missing default condition in a conditional node.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MissingDefaultConditionFlowValidationDetails {
    /// <p>The name of the node missing the default condition.</p>
    pub node: ::std::string::String,
}
impl MissingDefaultConditionFlowValidationDetails {
    /// <p>The name of the node missing the default condition.</p>
    pub fn node(&self) -> &str {
        use std::ops::Deref;
        self.node.deref()
    }
}
impl MissingDefaultConditionFlowValidationDetails {
    /// Creates a new builder-style object to manufacture [`MissingDefaultConditionFlowValidationDetails`](crate::types::MissingDefaultConditionFlowValidationDetails).
    pub fn builder() -> crate::types::builders::MissingDefaultConditionFlowValidationDetailsBuilder {
        crate::types::builders::MissingDefaultConditionFlowValidationDetailsBuilder::default()
    }
}

/// A builder for [`MissingDefaultConditionFlowValidationDetails`](crate::types::MissingDefaultConditionFlowValidationDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MissingDefaultConditionFlowValidationDetailsBuilder {
    pub(crate) node: ::std::option::Option<::std::string::String>,
}
impl MissingDefaultConditionFlowValidationDetailsBuilder {
    /// <p>The name of the node missing the default condition.</p>
    /// This field is required.
    pub fn node(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.node = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the node missing the default condition.</p>
    pub fn set_node(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.node = input;
        self
    }
    /// <p>The name of the node missing the default condition.</p>
    pub fn get_node(&self) -> &::std::option::Option<::std::string::String> {
        &self.node
    }
    /// Consumes the builder and constructs a [`MissingDefaultConditionFlowValidationDetails`](crate::types::MissingDefaultConditionFlowValidationDetails).
    /// This method will fail if any of the following fields are not set:
    /// - [`node`](crate::types::builders::MissingDefaultConditionFlowValidationDetailsBuilder::node)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::MissingDefaultConditionFlowValidationDetails, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::MissingDefaultConditionFlowValidationDetails {
            node: self.node.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "node",
                    "node was not specified but it is required when building MissingDefaultConditionFlowValidationDetails",
                )
            })?,
        })
    }
}
