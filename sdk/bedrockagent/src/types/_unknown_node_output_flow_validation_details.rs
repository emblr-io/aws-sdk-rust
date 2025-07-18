// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about an unknown output for a node.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UnknownNodeOutputFlowValidationDetails {
    /// <p>The name of the node with the unknown output.</p>
    pub node: ::std::string::String,
    /// <p>The name of the unknown output.</p>
    pub output: ::std::string::String,
}
impl UnknownNodeOutputFlowValidationDetails {
    /// <p>The name of the node with the unknown output.</p>
    pub fn node(&self) -> &str {
        use std::ops::Deref;
        self.node.deref()
    }
    /// <p>The name of the unknown output.</p>
    pub fn output(&self) -> &str {
        use std::ops::Deref;
        self.output.deref()
    }
}
impl UnknownNodeOutputFlowValidationDetails {
    /// Creates a new builder-style object to manufacture [`UnknownNodeOutputFlowValidationDetails`](crate::types::UnknownNodeOutputFlowValidationDetails).
    pub fn builder() -> crate::types::builders::UnknownNodeOutputFlowValidationDetailsBuilder {
        crate::types::builders::UnknownNodeOutputFlowValidationDetailsBuilder::default()
    }
}

/// A builder for [`UnknownNodeOutputFlowValidationDetails`](crate::types::UnknownNodeOutputFlowValidationDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UnknownNodeOutputFlowValidationDetailsBuilder {
    pub(crate) node: ::std::option::Option<::std::string::String>,
    pub(crate) output: ::std::option::Option<::std::string::String>,
}
impl UnknownNodeOutputFlowValidationDetailsBuilder {
    /// <p>The name of the node with the unknown output.</p>
    /// This field is required.
    pub fn node(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.node = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the node with the unknown output.</p>
    pub fn set_node(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.node = input;
        self
    }
    /// <p>The name of the node with the unknown output.</p>
    pub fn get_node(&self) -> &::std::option::Option<::std::string::String> {
        &self.node
    }
    /// <p>The name of the unknown output.</p>
    /// This field is required.
    pub fn output(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.output = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the unknown output.</p>
    pub fn set_output(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.output = input;
        self
    }
    /// <p>The name of the unknown output.</p>
    pub fn get_output(&self) -> &::std::option::Option<::std::string::String> {
        &self.output
    }
    /// Consumes the builder and constructs a [`UnknownNodeOutputFlowValidationDetails`](crate::types::UnknownNodeOutputFlowValidationDetails).
    /// This method will fail if any of the following fields are not set:
    /// - [`node`](crate::types::builders::UnknownNodeOutputFlowValidationDetailsBuilder::node)
    /// - [`output`](crate::types::builders::UnknownNodeOutputFlowValidationDetailsBuilder::output)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::UnknownNodeOutputFlowValidationDetails, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::UnknownNodeOutputFlowValidationDetails {
            node: self.node.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "node",
                    "node was not specified but it is required when building UnknownNodeOutputFlowValidationDetails",
                )
            })?,
            output: self.output.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "output",
                    "output was not specified but it is required when building UnknownNodeOutputFlowValidationDetails",
                )
            })?,
        })
    }
}
