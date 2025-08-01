// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about mismatched output data types in a node.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MismatchedNodeOutputTypeFlowValidationDetails {
    /// <p>The name of the node containing the output with the mismatched data type.</p>
    pub node: ::std::string::String,
    /// <p>The name of the output with the mismatched data type.</p>
    pub output: ::std::string::String,
    /// <p>The expected data type for the node output.</p>
    pub expected_type: crate::types::FlowNodeIoDataType,
}
impl MismatchedNodeOutputTypeFlowValidationDetails {
    /// <p>The name of the node containing the output with the mismatched data type.</p>
    pub fn node(&self) -> &str {
        use std::ops::Deref;
        self.node.deref()
    }
    /// <p>The name of the output with the mismatched data type.</p>
    pub fn output(&self) -> &str {
        use std::ops::Deref;
        self.output.deref()
    }
    /// <p>The expected data type for the node output.</p>
    pub fn expected_type(&self) -> &crate::types::FlowNodeIoDataType {
        &self.expected_type
    }
}
impl MismatchedNodeOutputTypeFlowValidationDetails {
    /// Creates a new builder-style object to manufacture [`MismatchedNodeOutputTypeFlowValidationDetails`](crate::types::MismatchedNodeOutputTypeFlowValidationDetails).
    pub fn builder() -> crate::types::builders::MismatchedNodeOutputTypeFlowValidationDetailsBuilder {
        crate::types::builders::MismatchedNodeOutputTypeFlowValidationDetailsBuilder::default()
    }
}

/// A builder for [`MismatchedNodeOutputTypeFlowValidationDetails`](crate::types::MismatchedNodeOutputTypeFlowValidationDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MismatchedNodeOutputTypeFlowValidationDetailsBuilder {
    pub(crate) node: ::std::option::Option<::std::string::String>,
    pub(crate) output: ::std::option::Option<::std::string::String>,
    pub(crate) expected_type: ::std::option::Option<crate::types::FlowNodeIoDataType>,
}
impl MismatchedNodeOutputTypeFlowValidationDetailsBuilder {
    /// <p>The name of the node containing the output with the mismatched data type.</p>
    /// This field is required.
    pub fn node(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.node = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the node containing the output with the mismatched data type.</p>
    pub fn set_node(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.node = input;
        self
    }
    /// <p>The name of the node containing the output with the mismatched data type.</p>
    pub fn get_node(&self) -> &::std::option::Option<::std::string::String> {
        &self.node
    }
    /// <p>The name of the output with the mismatched data type.</p>
    /// This field is required.
    pub fn output(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.output = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the output with the mismatched data type.</p>
    pub fn set_output(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.output = input;
        self
    }
    /// <p>The name of the output with the mismatched data type.</p>
    pub fn get_output(&self) -> &::std::option::Option<::std::string::String> {
        &self.output
    }
    /// <p>The expected data type for the node output.</p>
    /// This field is required.
    pub fn expected_type(mut self, input: crate::types::FlowNodeIoDataType) -> Self {
        self.expected_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The expected data type for the node output.</p>
    pub fn set_expected_type(mut self, input: ::std::option::Option<crate::types::FlowNodeIoDataType>) -> Self {
        self.expected_type = input;
        self
    }
    /// <p>The expected data type for the node output.</p>
    pub fn get_expected_type(&self) -> &::std::option::Option<crate::types::FlowNodeIoDataType> {
        &self.expected_type
    }
    /// Consumes the builder and constructs a [`MismatchedNodeOutputTypeFlowValidationDetails`](crate::types::MismatchedNodeOutputTypeFlowValidationDetails).
    /// This method will fail if any of the following fields are not set:
    /// - [`node`](crate::types::builders::MismatchedNodeOutputTypeFlowValidationDetailsBuilder::node)
    /// - [`output`](crate::types::builders::MismatchedNodeOutputTypeFlowValidationDetailsBuilder::output)
    /// - [`expected_type`](crate::types::builders::MismatchedNodeOutputTypeFlowValidationDetailsBuilder::expected_type)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::MismatchedNodeOutputTypeFlowValidationDetails, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::MismatchedNodeOutputTypeFlowValidationDetails {
            node: self.node.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "node",
                    "node was not specified but it is required when building MismatchedNodeOutputTypeFlowValidationDetails",
                )
            })?,
            output: self.output.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "output",
                    "output was not specified but it is required when building MismatchedNodeOutputTypeFlowValidationDetails",
                )
            })?,
            expected_type: self.expected_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "expected_type",
                    "expected_type was not specified but it is required when building MismatchedNodeOutputTypeFlowValidationDetails",
                )
            })?,
        })
    }
}
